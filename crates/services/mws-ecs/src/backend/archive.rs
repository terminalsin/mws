//! Image archives for `docker load`: an OCI image layout with Docker's
//! `manifest.json` beside it, as `docker save` writes. ECS hands the
//! container engine images from MWS's own ECR registry this way, so no
//! registry login or network pull is involved.

use crate::platform::RegistryImage;

/// The local reference an ECR image is loaded as.
pub fn local_tag(digest: &str) -> String {
    format!("mws-ecs:{}", digest.trim_start_matches("sha256:"))
}

/// The archive that loads `image` as `tag`.
pub fn image_archive(tag: &str, image: &RegistryImage) -> Vec<u8> {
    let hex = |d: &str| d.trim_start_matches("sha256:").to_string();
    let path = |d: &str| format!("blobs/sha256/{}", hex(d));
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": image.manifest_media_type,
            "digest": image.digest,
            "size": image.manifest.len(),
            "annotations": {
                "io.containerd.image.name": format!("docker.io/library/{tag}"),
                "org.opencontainers.image.ref.name": tag.rsplit_once(':').map_or(tag, |(_, t)| t),
            },
        }],
    });
    let docker_manifest = serde_json::json!([{
        "Config": path(&image.config_digest),
        "RepoTags": [tag],
        "Layers": image.layers.iter().map(|(d, _)| path(d)).collect::<Vec<_>>(),
    }]);
    let mut tar = Tar::default();
    tar.dir("blobs/");
    tar.dir("blobs/sha256/");
    tar.file(&path(&image.digest), &image.manifest);
    tar.file(&path(&image.config_digest), &image.config);
    let mut seen = std::collections::BTreeSet::new();
    for (d, data) in &image.layers {
        if seen.insert(d.clone()) {
            tar.file(&path(d), data);
        }
    }
    tar.file("index.json", index.to_string().as_bytes());
    tar.file("manifest.json", docker_manifest.to_string().as_bytes());
    tar.file("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    tar.finish()
}

/// A minimal ustar writer.
#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    fn header(&mut self, name: &str, size: usize, kind: u8, mode: &str) {
        let mut h = [0u8; 512];
        let put = |h: &mut [u8; 512], at: usize, v: &[u8]| h[at..at + v.len()].copy_from_slice(v);
        put(&mut h, 0, name.as_bytes());
        put(&mut h, 100, format!("{mode}\0").as_bytes());
        put(&mut h, 108, b"0000000\0");
        put(&mut h, 116, b"0000000\0");
        put(&mut h, 124, format!("{size:011o}\0").as_bytes());
        put(&mut h, 136, b"00000000000\0");
        put(&mut h, 148, b"        ");
        h[156] = kind;
        put(&mut h, 257, b"ustar\0");
        put(&mut h, 263, b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
        self.0.extend_from_slice(&h);
    }

    fn dir(&mut self, name: &str) {
        self.header(name, 0, b'5', "0000755");
    }

    fn file(&mut self, name: &str, data: &[u8]) {
        self.header(name, data.len(), b'0', "0000644");
        self.0.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.0.extend(std::iter::repeat_n(0u8, pad));
    }

    fn finish(mut self) -> Vec<u8> {
        self.0.extend(std::iter::repeat_n(0u8, 1024));
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archives_hold_the_manifest_config_and_layers() {
        let image = RegistryImage {
            resolved_digest: "sha256:aa".into(),
            digest: "sha256:aa".into(),
            manifest: bytes::Bytes::from_static(b"{}"),
            manifest_media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            config_digest: "sha256:bb".into(),
            config: bytes::Bytes::from_static(b"{\"os\":\"linux\"}"),
            layers: vec![("sha256:cc".into(), bytes::Bytes::from_static(b"layer"))],
        };
        let tag = local_tag("sha256:aa");
        assert_eq!(tag, "mws-ecs:aa");
        let a = image_archive(&tag, &image);
        assert_eq!(a.len() % 512, 0);
        let text = String::from_utf8_lossy(&a);
        for name in ["blobs/sha256/aa", "blobs/sha256/bb", "blobs/sha256/cc", "manifest.json", "index.json"] {
            assert!(text.contains(name), "{name} missing");
        }
        assert!(text.contains(r#""RepoTags":["mws-ecs:aa"]"#));
    }
}
