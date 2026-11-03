//! A subset of AWS managed policies, covering the services MWS emulates.
//! Documents are trimmed to the actions those services have; their names and
//! ARNs match AWS so code that attaches them works unchanged.

pub struct AwsManaged {
    pub name: &'static str,
    pub path: &'static str,
    pub description: &'static str,
    pub document: &'static str,
}

pub const POLICIES: &[AwsManaged] = &[
    AwsManaged {
        name: "AdministratorAccess",
        path: "/",
        description: "Provides full access to AWS services and resources.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "PowerUserAccess",
        path: "/",
        description:
            "Provides full access to AWS services and resources, but does not allow management of Users and groups.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions","account:GetAccountInformation"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "ReadOnlyAccess",
        path: "/",
        description: "Provides read-only access to AWS services and resources.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:Generate*","iam:Get*","iam:List*","iam:Simulate*","route53:Get*","route53:List*","route53:TestDNSAnswer","acm-pca:Describe*","acm-pca:Get*","acm-pca:List*","sts:GetCallerIdentity"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "IAMFullAccess",
        path: "/",
        description: "Provides full access to IAM via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit","organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents","organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies","organizations:ListTargetsForPolicy"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "IAMReadOnlyAccess",
        path: "/",
        description: "Provides read only access to IAM via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GenerateCredentialReport","iam:GenerateServiceLastAccessedDetails","iam:Get*","iam:List*","iam:SimulateCustomPolicy","iam:SimulatePrincipalPolicy"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "IAMUserChangePassword",
        path: "/",
        description: "Provides the ability for an IAM user to change their own password.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ChangePassword"],"Resource":["arn:aws:iam::*:user/${aws:username}"]},{"Effect":"Allow","Action":["iam:GetAccountPasswordPolicy"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "AmazonRoute53FullAccess",
        path: "/",
        description: "Provides full access to all Amazon Route 53 via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["route53:*","route53domains:*"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "AmazonRoute53ReadOnlyAccess",
        path: "/",
        description: "Provides read only access to all Amazon Route 53 via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["route53:Get*","route53:List*","route53:TestDNSAnswer"],"Resource":["*"]}]}"#,
    },
    AwsManaged {
        name: "AWSPrivateCAFullAccess",
        path: "/",
        description: "Provides full access to AWS Private CA.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["acm-pca:*"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "AWSPrivateCAReadOnly",
        path: "/",
        description: "Provides read only access to AWS Private CA.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["acm-pca:DescribeCertificateAuthority","acm-pca:DescribeCertificateAuthorityAuditReport","acm-pca:ListCertificateAuthorities","acm-pca:GetCertificateAuthorityCsr","acm-pca:GetCertificateAuthorityCertificate","acm-pca:GetCertificate","acm-pca:GetPolicy","acm-pca:ListPermissions","acm-pca:ListTags"],"Resource":"*"}]}"#,
    },
    AwsManaged {
        name: "AWSPrivateCAUser",
        path: "/",
        description: "Provides certificate user access to AWS Private CA.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["acm-pca:IssueCertificate"],"Resource":"*","Condition":{"StringLike":{"acm-pca:TemplateArn":["arn:aws:acm-pca:::template/EndEntityCertificate/V*"]}}},{"Effect":"Deny","Action":["acm-pca:IssueCertificate"],"Resource":"*","Condition":{"StringNotLike":{"acm-pca:TemplateArn":["arn:aws:acm-pca:::template/EndEntityCertificate/V*"]}}},{"Effect":"Allow","Action":["acm-pca:RevokeCertificate","acm-pca:GetCertificate","acm-pca:ListPermissions"],"Resource":"*"},{"Effect":"Allow","Action":["acm-pca:ListCertificateAuthorities"],"Resource":"*"}]}"#,
    },
];
