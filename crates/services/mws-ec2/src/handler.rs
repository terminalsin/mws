//! The generated `Handler`, forwarding to the operations in `ops`.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ec2;

#[async_trait::async_trait]
impl Handler for Ec2 {
    async fn allocate_address(
        &self,
        ctx: &RequestContext,
        input: types::AllocateAddressRequest,
    ) -> Result<types::AllocateAddressResult, ServiceError> {
        self.allocate_address_op(ctx, input)
    }
    async fn associate_address(
        &self,
        ctx: &RequestContext,
        input: types::AssociateAddressRequest,
    ) -> Result<types::AssociateAddressResult, ServiceError> {
        self.associate_address_op(ctx, input)
    }
    async fn associate_dhcp_options(
        &self,
        ctx: &RequestContext,
        input: types::AssociateDhcpOptionsRequest,
    ) -> Result<(), ServiceError> {
        self.associate_dhcp_options_op(ctx, input)
    }
    async fn associate_iam_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::AssociateIamInstanceProfileRequest,
    ) -> Result<types::AssociateIamInstanceProfileResult, ServiceError> {
        self.associate_iam_instance_profile_op(ctx, input)
    }
    async fn associate_route_table(
        &self,
        ctx: &RequestContext,
        input: types::AssociateRouteTableRequest,
    ) -> Result<types::AssociateRouteTableResult, ServiceError> {
        self.associate_route_table_op(ctx, input)
    }
    async fn associate_vpc_cidr_block(
        &self,
        ctx: &RequestContext,
        input: types::AssociateVpcCidrBlockRequest,
    ) -> Result<types::AssociateVpcCidrBlockResult, ServiceError> {
        self.associate_vpc_cidr_block_op(ctx, input)
    }
    async fn attach_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::AttachInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.attach_internet_gateway_op(ctx, input)
    }
    async fn attach_network_interface(
        &self,
        ctx: &RequestContext,
        input: types::AttachNetworkInterfaceRequest,
    ) -> Result<types::AttachNetworkInterfaceResult, ServiceError> {
        self.attach_network_interface_op(ctx, input)
    }
    async fn attach_volume(
        &self,
        ctx: &RequestContext,
        input: types::AttachVolumeRequest,
    ) -> Result<types::VolumeAttachment, ServiceError> {
        self.attach_volume_op(ctx, input)
    }
    async fn authorize_security_group_egress(
        &self,
        ctx: &RequestContext,
        input: types::AuthorizeSecurityGroupEgressRequest,
    ) -> Result<types::AuthorizeSecurityGroupEgressResult, ServiceError> {
        self.authorize_security_group_egress_op(ctx, input)
    }
    async fn authorize_security_group_ingress(
        &self,
        ctx: &RequestContext,
        input: types::AuthorizeSecurityGroupIngressRequest,
    ) -> Result<types::AuthorizeSecurityGroupIngressResult, ServiceError> {
        self.authorize_security_group_ingress_op(ctx, input)
    }
    async fn copy_image(
        &self,
        ctx: &RequestContext,
        input: types::CopyImageRequest,
    ) -> Result<types::CopyImageResult, ServiceError> {
        self.copy_image_op(ctx, input)
    }
    async fn create_default_subnet(
        &self,
        ctx: &RequestContext,
        input: types::CreateDefaultSubnetRequest,
    ) -> Result<types::CreateDefaultSubnetResult, ServiceError> {
        self.create_default_subnet_op(ctx, input)
    }
    async fn create_default_vpc(
        &self,
        ctx: &RequestContext,
        input: types::CreateDefaultVpcRequest,
    ) -> Result<types::CreateDefaultVpcResult, ServiceError> {
        self.create_default_vpc_op(ctx, input)
    }
    async fn create_dhcp_options(
        &self,
        ctx: &RequestContext,
        input: types::CreateDhcpOptionsRequest,
    ) -> Result<types::CreateDhcpOptionsResult, ServiceError> {
        self.create_dhcp_options_op(ctx, input)
    }
    async fn create_image(
        &self,
        ctx: &RequestContext,
        input: types::CreateImageRequest,
    ) -> Result<types::CreateImageResult, ServiceError> {
        self.create_image_op(ctx, input).await
    }
    async fn create_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateInternetGatewayRequest,
    ) -> Result<types::CreateInternetGatewayResult, ServiceError> {
        self.create_internet_gateway_op(ctx, input)
    }
    async fn create_key_pair(
        &self,
        ctx: &RequestContext,
        input: types::CreateKeyPairRequest,
    ) -> Result<types::KeyPair, ServiceError> {
        self.create_key_pair_op(ctx, input)
    }
    async fn create_nat_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateNatGatewayRequest,
    ) -> Result<types::CreateNatGatewayResult, ServiceError> {
        self.create_nat_gateway_op(ctx, input)
    }
    async fn create_network_acl(
        &self,
        ctx: &RequestContext,
        input: types::CreateNetworkAclRequest,
    ) -> Result<types::CreateNetworkAclResult, ServiceError> {
        self.create_network_acl_op(ctx, input)
    }
    async fn create_network_acl_entry(
        &self,
        ctx: &RequestContext,
        input: types::CreateNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        self.create_network_acl_entry_op(ctx, input)
    }
    async fn create_network_interface(
        &self,
        ctx: &RequestContext,
        input: types::CreateNetworkInterfaceRequest,
    ) -> Result<types::CreateNetworkInterfaceResult, ServiceError> {
        self.create_network_interface_op(ctx, input)
    }
    async fn create_route(
        &self,
        ctx: &RequestContext,
        input: types::CreateRouteRequest,
    ) -> Result<types::CreateRouteResult, ServiceError> {
        self.create_route_op(ctx, input)
    }
    async fn create_route_table(
        &self,
        ctx: &RequestContext,
        input: types::CreateRouteTableRequest,
    ) -> Result<types::CreateRouteTableResult, ServiceError> {
        self.create_route_table_op(ctx, input)
    }
    async fn create_security_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateSecurityGroupRequest,
    ) -> Result<types::CreateSecurityGroupResult, ServiceError> {
        self.create_security_group_op(ctx, input)
    }
    async fn create_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CreateSnapshotRequest,
    ) -> Result<types::Snapshot, ServiceError> {
        self.create_snapshot_op(ctx, input)
    }
    async fn create_subnet(
        &self,
        ctx: &RequestContext,
        input: types::CreateSubnetRequest,
    ) -> Result<types::CreateSubnetResult, ServiceError> {
        self.create_subnet_op(ctx, input)
    }
    async fn create_tags(&self, ctx: &RequestContext, input: types::CreateTagsRequest) -> Result<(), ServiceError> {
        self.create_tags_op(ctx, input)
    }
    async fn create_volume(
        &self,
        ctx: &RequestContext,
        input: types::CreateVolumeRequest,
    ) -> Result<types::Volume, ServiceError> {
        self.create_volume_op(ctx, input)
    }
    async fn create_vpc(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpcRequest,
    ) -> Result<types::CreateVpcResult, ServiceError> {
        self.create_vpc_op(ctx, input)
    }
    async fn delete_dhcp_options(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDhcpOptionsRequest,
    ) -> Result<(), ServiceError> {
        self.delete_dhcp_options_op(ctx, input)
    }
    async fn delete_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.delete_internet_gateway_op(ctx, input)
    }
    async fn delete_key_pair(
        &self,
        ctx: &RequestContext,
        input: types::DeleteKeyPairRequest,
    ) -> Result<types::DeleteKeyPairResult, ServiceError> {
        self.delete_key_pair_op(ctx, input)
    }
    async fn delete_nat_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNatGatewayRequest,
    ) -> Result<types::DeleteNatGatewayResult, ServiceError> {
        self.delete_nat_gateway_op(ctx, input)
    }
    async fn delete_network_acl(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNetworkAclRequest,
    ) -> Result<(), ServiceError> {
        self.delete_network_acl_op(ctx, input)
    }
    async fn delete_network_acl_entry(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        self.delete_network_acl_entry_op(ctx, input)
    }
    async fn delete_network_interface(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNetworkInterfaceRequest,
    ) -> Result<(), ServiceError> {
        self.delete_network_interface_op(ctx, input)
    }
    async fn delete_route(&self, ctx: &RequestContext, input: types::DeleteRouteRequest) -> Result<(), ServiceError> {
        self.delete_route_op(ctx, input)
    }
    async fn delete_route_table(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRouteTableRequest,
    ) -> Result<(), ServiceError> {
        self.delete_route_table_op(ctx, input)
    }
    async fn delete_security_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSecurityGroupRequest,
    ) -> Result<types::DeleteSecurityGroupResult, ServiceError> {
        self.delete_security_group_op(ctx, input)
    }
    async fn delete_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSnapshotRequest,
    ) -> Result<(), ServiceError> {
        self.delete_snapshot_op(ctx, input)
    }
    async fn delete_subnet(&self, ctx: &RequestContext, input: types::DeleteSubnetRequest) -> Result<(), ServiceError> {
        self.delete_subnet_op(ctx, input)
    }
    async fn delete_tags(&self, ctx: &RequestContext, input: types::DeleteTagsRequest) -> Result<(), ServiceError> {
        self.delete_tags_op(ctx, input)
    }
    async fn delete_volume(&self, ctx: &RequestContext, input: types::DeleteVolumeRequest) -> Result<(), ServiceError> {
        self.delete_volume_op(ctx, input)
    }
    async fn delete_vpc(&self, ctx: &RequestContext, input: types::DeleteVpcRequest) -> Result<(), ServiceError> {
        self.delete_vpc_op(ctx, input)
    }
    async fn deregister_image(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterImageRequest,
    ) -> Result<types::DeregisterImageResult, ServiceError> {
        self.deregister_image_op(ctx, input)
    }
    async fn describe_account_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountAttributesRequest,
    ) -> Result<types::DescribeAccountAttributesResult, ServiceError> {
        self.describe_account_attributes_op(ctx, input)
    }
    async fn describe_addresses(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddressesRequest,
    ) -> Result<types::DescribeAddressesResult, ServiceError> {
        self.describe_addresses_op(ctx, input)
    }
    async fn describe_availability_zones(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAvailabilityZonesRequest,
    ) -> Result<types::DescribeAvailabilityZonesResult, ServiceError> {
        self.describe_availability_zones_op(ctx, input)
    }
    async fn describe_dhcp_options(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDhcpOptionsRequest,
    ) -> Result<types::DescribeDhcpOptionsResult, ServiceError> {
        self.describe_dhcp_options_op(ctx, input)
    }
    async fn describe_iam_instance_profile_associations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeIamInstanceProfileAssociationsRequest,
    ) -> Result<types::DescribeIamInstanceProfileAssociationsResult, ServiceError> {
        self.describe_iam_instance_profile_associations_op(ctx, input)
    }
    async fn describe_image_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImageAttributeRequest,
    ) -> Result<types::ImageAttribute, ServiceError> {
        self.describe_image_attribute_op(ctx, input)
    }
    async fn describe_images(
        &self,
        ctx: &RequestContext,
        input: types::DescribeImagesRequest,
    ) -> Result<types::DescribeImagesResult, ServiceError> {
        self.describe_images_op(ctx, input)
    }
    async fn describe_instance_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceAttributeRequest,
    ) -> Result<types::InstanceAttribute, ServiceError> {
        self.describe_instance_attribute_op(ctx, input)
    }
    async fn describe_instance_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceStatusRequest,
    ) -> Result<types::DescribeInstanceStatusResult, ServiceError> {
        self.describe_instance_status_op(ctx, input)
    }
    async fn describe_instance_type_offerings(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceTypeOfferingsRequest,
    ) -> Result<types::DescribeInstanceTypeOfferingsResult, ServiceError> {
        self.describe_instance_type_offerings_op(ctx, input)
    }
    async fn describe_instance_types(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceTypesRequest,
    ) -> Result<types::DescribeInstanceTypesResult, ServiceError> {
        self.describe_instance_types_op(ctx, input)
    }
    async fn describe_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstancesRequest,
    ) -> Result<types::DescribeInstancesResult, ServiceError> {
        self.describe_instances_op(ctx, input)
    }
    async fn describe_internet_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInternetGatewaysRequest,
    ) -> Result<types::DescribeInternetGatewaysResult, ServiceError> {
        self.describe_internet_gateways_op(ctx, input)
    }
    async fn describe_key_pairs(
        &self,
        ctx: &RequestContext,
        input: types::DescribeKeyPairsRequest,
    ) -> Result<types::DescribeKeyPairsResult, ServiceError> {
        self.describe_key_pairs_op(ctx, input)
    }
    async fn describe_nat_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNatGatewaysRequest,
    ) -> Result<types::DescribeNatGatewaysResult, ServiceError> {
        self.describe_nat_gateways_op(ctx, input)
    }
    async fn describe_network_acls(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNetworkAclsRequest,
    ) -> Result<types::DescribeNetworkAclsResult, ServiceError> {
        self.describe_network_acls_op(ctx, input)
    }
    async fn describe_network_interfaces(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNetworkInterfacesRequest,
    ) -> Result<types::DescribeNetworkInterfacesResult, ServiceError> {
        self.describe_network_interfaces_op(ctx, input)
    }
    async fn describe_regions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRegionsRequest,
    ) -> Result<types::DescribeRegionsResult, ServiceError> {
        self.describe_regions_op(ctx, input)
    }
    async fn describe_route_tables(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRouteTablesRequest,
    ) -> Result<types::DescribeRouteTablesResult, ServiceError> {
        self.describe_route_tables_op(ctx, input)
    }
    async fn describe_security_group_rules(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSecurityGroupRulesRequest,
    ) -> Result<types::DescribeSecurityGroupRulesResult, ServiceError> {
        self.describe_security_group_rules_op(ctx, input)
    }
    async fn describe_security_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSecurityGroupsRequest,
    ) -> Result<types::DescribeSecurityGroupsResult, ServiceError> {
        self.describe_security_groups_op(ctx, input)
    }
    async fn describe_snapshots(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSnapshotsRequest,
    ) -> Result<types::DescribeSnapshotsResult, ServiceError> {
        self.describe_snapshots_op(ctx, input)
    }
    async fn describe_subnets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSubnetsRequest,
    ) -> Result<types::DescribeSubnetsResult, ServiceError> {
        self.describe_subnets_op(ctx, input)
    }
    async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTagsRequest,
    ) -> Result<types::DescribeTagsResult, ServiceError> {
        self.describe_tags_op(ctx, input)
    }
    async fn describe_volumes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVolumesRequest,
    ) -> Result<types::DescribeVolumesResult, ServiceError> {
        self.describe_volumes_op(ctx, input)
    }
    async fn describe_vpc_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcAttributeRequest,
    ) -> Result<types::DescribeVpcAttributeResult, ServiceError> {
        self.describe_vpc_attribute_op(ctx, input)
    }
    async fn describe_vpcs(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcsRequest,
    ) -> Result<types::DescribeVpcsResult, ServiceError> {
        self.describe_vpcs_op(ctx, input)
    }
    async fn detach_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DetachInternetGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.detach_internet_gateway_op(ctx, input)
    }
    async fn detach_network_interface(
        &self,
        ctx: &RequestContext,
        input: types::DetachNetworkInterfaceRequest,
    ) -> Result<(), ServiceError> {
        self.detach_network_interface_op(ctx, input)
    }
    async fn detach_volume(
        &self,
        ctx: &RequestContext,
        input: types::DetachVolumeRequest,
    ) -> Result<types::VolumeAttachment, ServiceError> {
        self.detach_volume_op(ctx, input)
    }
    async fn disassociate_address(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateAddressRequest,
    ) -> Result<(), ServiceError> {
        self.disassociate_address_op(ctx, input)
    }
    async fn disassociate_iam_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateIamInstanceProfileRequest,
    ) -> Result<types::DisassociateIamInstanceProfileResult, ServiceError> {
        self.disassociate_iam_instance_profile_op(ctx, input)
    }
    async fn disassociate_route_table(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateRouteTableRequest,
    ) -> Result<(), ServiceError> {
        self.disassociate_route_table_op(ctx, input)
    }
    async fn disassociate_vpc_cidr_block(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateVpcCidrBlockRequest,
    ) -> Result<types::DisassociateVpcCidrBlockResult, ServiceError> {
        self.disassociate_vpc_cidr_block_op(ctx, input)
    }
    async fn get_console_output(
        &self,
        ctx: &RequestContext,
        input: types::GetConsoleOutputRequest,
    ) -> Result<types::GetConsoleOutputResult, ServiceError> {
        self.get_console_output_op(ctx, input).await
    }
    async fn import_key_pair(
        &self,
        ctx: &RequestContext,
        input: types::ImportKeyPairRequest,
    ) -> Result<types::ImportKeyPairResult, ServiceError> {
        self.import_key_pair_op(ctx, input)
    }
    async fn modify_image_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyImageAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_image_attribute_op(ctx, input)
    }
    async fn modify_instance_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyInstanceAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_instance_attribute_op(ctx, input)
    }
    async fn modify_instance_metadata_options(
        &self,
        ctx: &RequestContext,
        input: types::ModifyInstanceMetadataOptionsRequest,
    ) -> Result<types::ModifyInstanceMetadataOptionsResult, ServiceError> {
        self.modify_instance_metadata_options_op(ctx, input)
    }
    async fn modify_network_interface_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyNetworkInterfaceAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_network_interface_attribute_op(ctx, input)
    }
    async fn modify_security_group_rules(
        &self,
        ctx: &RequestContext,
        input: types::ModifySecurityGroupRulesRequest,
    ) -> Result<types::ModifySecurityGroupRulesResult, ServiceError> {
        self.modify_security_group_rules_op(ctx, input)
    }
    async fn modify_subnet_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifySubnetAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_subnet_attribute_op(ctx, input)
    }
    async fn modify_vpc_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVpcAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_vpc_attribute_op(ctx, input)
    }
    async fn reboot_instances(
        &self,
        ctx: &RequestContext,
        input: types::RebootInstancesRequest,
    ) -> Result<(), ServiceError> {
        self.reboot_instances_op(ctx, input).await
    }
    async fn register_image(
        &self,
        ctx: &RequestContext,
        input: types::RegisterImageRequest,
    ) -> Result<types::RegisterImageResult, ServiceError> {
        self.register_image_op(ctx, input)
    }
    async fn release_address(
        &self,
        ctx: &RequestContext,
        input: types::ReleaseAddressRequest,
    ) -> Result<(), ServiceError> {
        self.release_address_op(ctx, input)
    }
    async fn replace_iam_instance_profile_association(
        &self,
        ctx: &RequestContext,
        input: types::ReplaceIamInstanceProfileAssociationRequest,
    ) -> Result<types::ReplaceIamInstanceProfileAssociationResult, ServiceError> {
        self.replace_iam_instance_profile_association_op(ctx, input)
    }
    async fn replace_network_acl_association(
        &self,
        ctx: &RequestContext,
        input: types::ReplaceNetworkAclAssociationRequest,
    ) -> Result<types::ReplaceNetworkAclAssociationResult, ServiceError> {
        self.replace_network_acl_association_op(ctx, input)
    }
    async fn replace_network_acl_entry(
        &self,
        ctx: &RequestContext,
        input: types::ReplaceNetworkAclEntryRequest,
    ) -> Result<(), ServiceError> {
        self.replace_network_acl_entry_op(ctx, input)
    }
    async fn replace_route(&self, ctx: &RequestContext, input: types::ReplaceRouteRequest) -> Result<(), ServiceError> {
        self.replace_route_op(ctx, input)
    }
    async fn replace_route_table_association(
        &self,
        ctx: &RequestContext,
        input: types::ReplaceRouteTableAssociationRequest,
    ) -> Result<types::ReplaceRouteTableAssociationResult, ServiceError> {
        self.replace_route_table_association_op(ctx, input)
    }
    async fn revoke_security_group_egress(
        &self,
        ctx: &RequestContext,
        input: types::RevokeSecurityGroupEgressRequest,
    ) -> Result<types::RevokeSecurityGroupEgressResult, ServiceError> {
        self.revoke_security_group_egress_op(ctx, input)
    }
    async fn revoke_security_group_ingress(
        &self,
        ctx: &RequestContext,
        input: types::RevokeSecurityGroupIngressRequest,
    ) -> Result<types::RevokeSecurityGroupIngressResult, ServiceError> {
        self.revoke_security_group_ingress_op(ctx, input)
    }
    async fn run_instances(
        &self,
        ctx: &RequestContext,
        input: types::RunInstancesRequest,
    ) -> Result<types::Reservation, ServiceError> {
        self.run_instances_op(ctx, input).await
    }
    async fn start_instances(
        &self,
        ctx: &RequestContext,
        input: types::StartInstancesRequest,
    ) -> Result<types::StartInstancesResult, ServiceError> {
        self.start_instances_op(ctx, input).await
    }
    async fn stop_instances(
        &self,
        ctx: &RequestContext,
        input: types::StopInstancesRequest,
    ) -> Result<types::StopInstancesResult, ServiceError> {
        self.stop_instances_op(ctx, input).await
    }
    async fn terminate_instances(
        &self,
        ctx: &RequestContext,
        input: types::TerminateInstancesRequest,
    ) -> Result<types::TerminateInstancesResult, ServiceError> {
        self.terminate_instances_op(ctx, input).await
    }
    async fn update_security_group_rule_descriptions_egress(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityGroupRuleDescriptionsEgressRequest,
    ) -> Result<types::UpdateSecurityGroupRuleDescriptionsEgressResult, ServiceError> {
        self.update_security_group_rule_descriptions_egress_op(ctx, input)
    }
    async fn update_security_group_rule_descriptions_ingress(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityGroupRuleDescriptionsIngressRequest,
    ) -> Result<types::UpdateSecurityGroupRuleDescriptionsIngressResult, ServiceError> {
        self.update_security_group_rule_descriptions_ingress_op(ctx, input)
    }
    // VPC endpoints, prefix lists and Elastic IP attributes
    async fn create_vpc_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpcEndpointRequest,
    ) -> Result<types::CreateVpcEndpointResult, ServiceError> {
        self.create_vpc_endpoint_op(ctx, input)
    }
    async fn delete_vpc_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVpcEndpointsRequest,
    ) -> Result<types::DeleteVpcEndpointsResult, ServiceError> {
        self.delete_vpc_endpoints_op(ctx, input)
    }
    async fn describe_vpc_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcEndpointsRequest,
    ) -> Result<types::DescribeVpcEndpointsResult, ServiceError> {
        self.describe_vpc_endpoints_op(ctx, input)
    }
    async fn modify_vpc_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVpcEndpointRequest,
    ) -> Result<types::ModifyVpcEndpointResult, ServiceError> {
        self.modify_vpc_endpoint_op(ctx, input)
    }
    async fn describe_vpc_endpoint_services(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcEndpointServicesRequest,
    ) -> Result<types::DescribeVpcEndpointServicesResult, ServiceError> {
        self.describe_vpc_endpoint_services_op(ctx, input)
    }
    async fn describe_prefix_lists(
        &self,
        ctx: &RequestContext,
        input: types::DescribePrefixListsRequest,
    ) -> Result<types::DescribePrefixListsResult, ServiceError> {
        self.describe_prefix_lists_op(ctx, input)
    }
    async fn describe_managed_prefix_lists(
        &self,
        ctx: &RequestContext,
        input: types::DescribeManagedPrefixListsRequest,
    ) -> Result<types::DescribeManagedPrefixListsResult, ServiceError> {
        self.describe_managed_prefix_lists_op(ctx, input)
    }
    async fn get_managed_prefix_list_entries(
        &self,
        ctx: &RequestContext,
        input: types::GetManagedPrefixListEntriesRequest,
    ) -> Result<types::GetManagedPrefixListEntriesResult, ServiceError> {
        self.get_managed_prefix_list_entries_op(ctx, input)
    }
    async fn create_managed_prefix_list(
        &self,
        ctx: &RequestContext,
        input: types::CreateManagedPrefixListRequest,
    ) -> Result<types::CreateManagedPrefixListResult, ServiceError> {
        self.create_managed_prefix_list_op(ctx, input)
    }
    async fn modify_managed_prefix_list(
        &self,
        ctx: &RequestContext,
        input: types::ModifyManagedPrefixListRequest,
    ) -> Result<types::ModifyManagedPrefixListResult, ServiceError> {
        self.modify_managed_prefix_list_op(ctx, input)
    }
    async fn delete_managed_prefix_list(
        &self,
        ctx: &RequestContext,
        input: types::DeleteManagedPrefixListRequest,
    ) -> Result<types::DeleteManagedPrefixListResult, ServiceError> {
        self.delete_managed_prefix_list_op(ctx, input)
    }
    async fn get_managed_prefix_list_associations(
        &self,
        ctx: &RequestContext,
        input: types::GetManagedPrefixListAssociationsRequest,
    ) -> Result<types::GetManagedPrefixListAssociationsResult, ServiceError> {
        self.get_managed_prefix_list_associations_op(ctx, input)
    }
    async fn describe_addresses_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddressesAttributeRequest,
    ) -> Result<types::DescribeAddressesAttributeResult, ServiceError> {
        self.describe_addresses_attribute_op(ctx, input)
    }
    async fn modify_address_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyAddressAttributeRequest,
    ) -> Result<types::ModifyAddressAttributeResult, ServiceError> {
        self.modify_address_attribute_op(ctx, input)
    }
    async fn reset_address_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ResetAddressAttributeRequest,
    ) -> Result<types::ResetAddressAttributeResult, ServiceError> {
        self.reset_address_attribute_op(ctx, input)
    }
    async fn copy_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CopySnapshotRequest,
    ) -> Result<types::CopySnapshotResult, ServiceError> {
        self.copy_snapshot_op(ctx, input)
    }
    async fn copy_volumes(
        &self,
        ctx: &RequestContext,
        input: types::CopyVolumesRequest,
    ) -> Result<types::CopyVolumesResult, ServiceError> {
        self.copy_volumes_op(ctx, input)
    }
    async fn create_launch_template(
        &self,
        ctx: &RequestContext,
        input: types::CreateLaunchTemplateRequest,
    ) -> Result<types::CreateLaunchTemplateResult, ServiceError> {
        self.create_launch_template_op(ctx, input)
    }
    async fn create_launch_template_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateLaunchTemplateVersionRequest,
    ) -> Result<types::CreateLaunchTemplateVersionResult, ServiceError> {
        self.create_launch_template_version_op(ctx, input)
    }
    async fn create_replace_root_volume_task(
        &self,
        ctx: &RequestContext,
        input: types::CreateReplaceRootVolumeTaskRequest,
    ) -> Result<types::CreateReplaceRootVolumeTaskResult, ServiceError> {
        self.create_replace_root_volume_task_op(ctx, input)
    }
    async fn create_snapshots(
        &self,
        ctx: &RequestContext,
        input: types::CreateSnapshotsRequest,
    ) -> Result<types::CreateSnapshotsResult, ServiceError> {
        self.create_snapshots_op(ctx, input)
    }
    async fn delete_launch_template(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLaunchTemplateRequest,
    ) -> Result<types::DeleteLaunchTemplateResult, ServiceError> {
        self.delete_launch_template_op(ctx, input)
    }
    async fn delete_launch_template_versions(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLaunchTemplateVersionsRequest,
    ) -> Result<types::DeleteLaunchTemplateVersionsResult, ServiceError> {
        self.delete_launch_template_versions_op(ctx, input)
    }
    async fn describe_fast_snapshot_restores(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFastSnapshotRestoresRequest,
    ) -> Result<types::DescribeFastSnapshotRestoresResult, ServiceError> {
        self.describe_fast_snapshot_restores_op(ctx, input)
    }
    async fn describe_launch_template_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLaunchTemplateVersionsRequest,
    ) -> Result<types::DescribeLaunchTemplateVersionsResult, ServiceError> {
        self.describe_launch_template_versions_op(ctx, input)
    }
    async fn describe_launch_templates(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLaunchTemplatesRequest,
    ) -> Result<types::DescribeLaunchTemplatesResult, ServiceError> {
        self.describe_launch_templates_op(ctx, input)
    }
    async fn describe_locked_snapshots(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLockedSnapshotsRequest,
    ) -> Result<types::DescribeLockedSnapshotsResult, ServiceError> {
        self.describe_locked_snapshots_op(ctx, input)
    }
    async fn describe_replace_root_volume_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReplaceRootVolumeTasksRequest,
    ) -> Result<types::DescribeReplaceRootVolumeTasksResult, ServiceError> {
        self.describe_replace_root_volume_tasks_op(ctx, input)
    }
    async fn describe_snapshot_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSnapshotAttributeRequest,
    ) -> Result<types::DescribeSnapshotAttributeResult, ServiceError> {
        self.describe_snapshot_attribute_op(ctx, input)
    }
    async fn describe_snapshot_tier_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSnapshotTierStatusRequest,
    ) -> Result<types::DescribeSnapshotTierStatusResult, ServiceError> {
        self.describe_snapshot_tier_status_op(ctx, input)
    }
    async fn describe_volume_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVolumeAttributeRequest,
    ) -> Result<types::DescribeVolumeAttributeResult, ServiceError> {
        self.describe_volume_attribute_op(ctx, input)
    }
    async fn describe_volume_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVolumeStatusRequest,
    ) -> Result<types::DescribeVolumeStatusResult, ServiceError> {
        self.describe_volume_status_op(ctx, input)
    }
    async fn describe_volumes_modifications(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVolumesModificationsRequest,
    ) -> Result<types::DescribeVolumesModificationsResult, ServiceError> {
        self.describe_volumes_modifications_op(ctx, input)
    }
    async fn disable_ebs_encryption_by_default(
        &self,
        ctx: &RequestContext,
        input: types::DisableEbsEncryptionByDefaultRequest,
    ) -> Result<types::DisableEbsEncryptionByDefaultResult, ServiceError> {
        self.disable_ebs_encryption_by_default_op(ctx, input)
    }
    async fn disable_fast_snapshot_restores(
        &self,
        ctx: &RequestContext,
        input: types::DisableFastSnapshotRestoresRequest,
    ) -> Result<types::DisableFastSnapshotRestoresResult, ServiceError> {
        self.disable_fast_snapshot_restores_op(ctx, input)
    }
    async fn disable_snapshot_block_public_access(
        &self,
        ctx: &RequestContext,
        input: types::DisableSnapshotBlockPublicAccessRequest,
    ) -> Result<types::DisableSnapshotBlockPublicAccessResult, ServiceError> {
        self.disable_snapshot_block_public_access_op(ctx, input)
    }
    async fn enable_ebs_encryption_by_default(
        &self,
        ctx: &RequestContext,
        input: types::EnableEbsEncryptionByDefaultRequest,
    ) -> Result<types::EnableEbsEncryptionByDefaultResult, ServiceError> {
        self.enable_ebs_encryption_by_default_op(ctx, input)
    }
    async fn enable_fast_snapshot_restores(
        &self,
        ctx: &RequestContext,
        input: types::EnableFastSnapshotRestoresRequest,
    ) -> Result<types::EnableFastSnapshotRestoresResult, ServiceError> {
        self.enable_fast_snapshot_restores_op(ctx, input)
    }
    async fn enable_snapshot_block_public_access(
        &self,
        ctx: &RequestContext,
        input: types::EnableSnapshotBlockPublicAccessRequest,
    ) -> Result<types::EnableSnapshotBlockPublicAccessResult, ServiceError> {
        self.enable_snapshot_block_public_access_op(ctx, input)
    }
    async fn enable_volume_io(
        &self,
        ctx: &RequestContext,
        input: types::EnableVolumeIORequest,
    ) -> Result<(), ServiceError> {
        self.enable_volume_io_op(ctx, input)
    }
    async fn get_ebs_default_kms_key_id(
        &self,
        ctx: &RequestContext,
        input: types::GetEbsDefaultKmsKeyIdRequest,
    ) -> Result<types::GetEbsDefaultKmsKeyIdResult, ServiceError> {
        self.get_ebs_default_kms_key_id_op(ctx, input)
    }
    async fn get_ebs_encryption_by_default(
        &self,
        ctx: &RequestContext,
        input: types::GetEbsEncryptionByDefaultRequest,
    ) -> Result<types::GetEbsEncryptionByDefaultResult, ServiceError> {
        self.get_ebs_encryption_by_default_op(ctx, input)
    }
    async fn get_launch_template_data(
        &self,
        ctx: &RequestContext,
        input: types::GetLaunchTemplateDataRequest,
    ) -> Result<types::GetLaunchTemplateDataResult, ServiceError> {
        self.get_launch_template_data_op(ctx, input)
    }
    async fn get_snapshot_block_public_access_state(
        &self,
        ctx: &RequestContext,
        input: types::GetSnapshotBlockPublicAccessStateRequest,
    ) -> Result<types::GetSnapshotBlockPublicAccessStateResult, ServiceError> {
        self.get_snapshot_block_public_access_state_op(ctx, input)
    }
    async fn list_snapshots_in_recycle_bin(
        &self,
        ctx: &RequestContext,
        input: types::ListSnapshotsInRecycleBinRequest,
    ) -> Result<types::ListSnapshotsInRecycleBinResult, ServiceError> {
        self.list_snapshots_in_recycle_bin_op(ctx, input)
    }
    async fn list_volumes_in_recycle_bin(
        &self,
        ctx: &RequestContext,
        input: types::ListVolumesInRecycleBinRequest,
    ) -> Result<types::ListVolumesInRecycleBinResult, ServiceError> {
        self.list_volumes_in_recycle_bin_op(ctx, input)
    }
    async fn lock_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::LockSnapshotRequest,
    ) -> Result<types::LockSnapshotResult, ServiceError> {
        self.lock_snapshot_op(ctx, input)
    }
    async fn modify_ebs_default_kms_key_id(
        &self,
        ctx: &RequestContext,
        input: types::ModifyEbsDefaultKmsKeyIdRequest,
    ) -> Result<types::ModifyEbsDefaultKmsKeyIdResult, ServiceError> {
        self.modify_ebs_default_kms_key_id_op(ctx, input)
    }
    async fn modify_launch_template(
        &self,
        ctx: &RequestContext,
        input: types::ModifyLaunchTemplateRequest,
    ) -> Result<types::ModifyLaunchTemplateResult, ServiceError> {
        self.modify_launch_template_op(ctx, input)
    }
    async fn modify_snapshot_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifySnapshotAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_snapshot_attribute_op(ctx, input)
    }
    async fn modify_snapshot_tier(
        &self,
        ctx: &RequestContext,
        input: types::ModifySnapshotTierRequest,
    ) -> Result<types::ModifySnapshotTierResult, ServiceError> {
        self.modify_snapshot_tier_op(ctx, input)
    }
    async fn modify_volume(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVolumeRequest,
    ) -> Result<types::ModifyVolumeResult, ServiceError> {
        self.modify_volume_op(ctx, input)
    }
    async fn modify_volume_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVolumeAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.modify_volume_attribute_op(ctx, input)
    }
    async fn reset_ebs_default_kms_key_id(
        &self,
        ctx: &RequestContext,
        input: types::ResetEbsDefaultKmsKeyIdRequest,
    ) -> Result<types::ResetEbsDefaultKmsKeyIdResult, ServiceError> {
        self.reset_ebs_default_kms_key_id_op(ctx, input)
    }
    async fn reset_snapshot_attribute(
        &self,
        ctx: &RequestContext,
        input: types::ResetSnapshotAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.reset_snapshot_attribute_op(ctx, input)
    }
    async fn restore_snapshot_from_recycle_bin(
        &self,
        ctx: &RequestContext,
        input: types::RestoreSnapshotFromRecycleBinRequest,
    ) -> Result<types::RestoreSnapshotFromRecycleBinResult, ServiceError> {
        self.restore_snapshot_from_recycle_bin_op(ctx, input)
    }
    async fn restore_snapshot_tier(
        &self,
        ctx: &RequestContext,
        input: types::RestoreSnapshotTierRequest,
    ) -> Result<types::RestoreSnapshotTierResult, ServiceError> {
        self.restore_snapshot_tier_op(ctx, input)
    }
    async fn restore_volume_from_recycle_bin(
        &self,
        ctx: &RequestContext,
        input: types::RestoreVolumeFromRecycleBinRequest,
    ) -> Result<types::RestoreVolumeFromRecycleBinResult, ServiceError> {
        self.restore_volume_from_recycle_bin_op(ctx, input)
    }
    async fn unlock_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::UnlockSnapshotRequest,
    ) -> Result<types::UnlockSnapshotResult, ServiceError> {
        self.unlock_snapshot_op(ctx, input)
    }
    async fn create_egress_only_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateEgressOnlyInternetGatewayRequest,
    ) -> Result<types::CreateEgressOnlyInternetGatewayResult, ServiceError> {
        self.create_egress_only_internet_gateway_op(ctx, input)
    }
    async fn delete_egress_only_internet_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEgressOnlyInternetGatewayRequest,
    ) -> Result<types::DeleteEgressOnlyInternetGatewayResult, ServiceError> {
        self.delete_egress_only_internet_gateway_op(ctx, input)
    }
    async fn describe_egress_only_internet_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEgressOnlyInternetGatewaysRequest,
    ) -> Result<types::DescribeEgressOnlyInternetGatewaysResult, ServiceError> {
        self.describe_egress_only_internet_gateways_op(ctx, input)
    }
    async fn create_carrier_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateCarrierGatewayRequest,
    ) -> Result<types::CreateCarrierGatewayResult, ServiceError> {
        self.create_carrier_gateway_op(ctx, input)
    }
    async fn delete_carrier_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCarrierGatewayRequest,
    ) -> Result<types::DeleteCarrierGatewayResult, ServiceError> {
        self.delete_carrier_gateway_op(ctx, input)
    }
    async fn describe_carrier_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCarrierGatewaysRequest,
    ) -> Result<types::DescribeCarrierGatewaysResult, ServiceError> {
        self.describe_carrier_gateways_op(ctx, input)
    }
    async fn create_customer_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomerGatewayRequest,
    ) -> Result<types::CreateCustomerGatewayResult, ServiceError> {
        self.create_customer_gateway_op(ctx, input)
    }
    async fn delete_customer_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomerGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.delete_customer_gateway_op(ctx, input)
    }
    async fn describe_customer_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCustomerGatewaysRequest,
    ) -> Result<types::DescribeCustomerGatewaysResult, ServiceError> {
        self.describe_customer_gateways_op(ctx, input)
    }
    async fn create_vpn_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpnGatewayRequest,
    ) -> Result<types::CreateVpnGatewayResult, ServiceError> {
        self.create_vpn_gateway_op(ctx, input)
    }
    async fn delete_vpn_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVpnGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.delete_vpn_gateway_op(ctx, input)
    }
    async fn describe_vpn_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpnGatewaysRequest,
    ) -> Result<types::DescribeVpnGatewaysResult, ServiceError> {
        self.describe_vpn_gateways_op(ctx, input)
    }
    async fn attach_vpn_gateway(
        &self,
        ctx: &RequestContext,
        input: types::AttachVpnGatewayRequest,
    ) -> Result<types::AttachVpnGatewayResult, ServiceError> {
        self.attach_vpn_gateway_op(ctx, input)
    }
    async fn detach_vpn_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DetachVpnGatewayRequest,
    ) -> Result<(), ServiceError> {
        self.detach_vpn_gateway_op(ctx, input)
    }
    async fn enable_vgw_route_propagation(
        &self,
        ctx: &RequestContext,
        input: types::EnableVgwRoutePropagationRequest,
    ) -> Result<(), ServiceError> {
        self.enable_vgw_route_propagation_op(ctx, input)
    }
    async fn disable_vgw_route_propagation(
        &self,
        ctx: &RequestContext,
        input: types::DisableVgwRoutePropagationRequest,
    ) -> Result<(), ServiceError> {
        self.disable_vgw_route_propagation_op(ctx, input)
    }
    async fn create_vpn_connection(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpnConnectionRequest,
    ) -> Result<types::CreateVpnConnectionResult, ServiceError> {
        self.create_vpn_connection_op(ctx, input)
    }
    async fn delete_vpn_connection(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVpnConnectionRequest,
    ) -> Result<(), ServiceError> {
        self.delete_vpn_connection_op(ctx, input)
    }
    async fn describe_vpn_connections(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpnConnectionsRequest,
    ) -> Result<types::DescribeVpnConnectionsResult, ServiceError> {
        self.describe_vpn_connections_op(ctx, input)
    }
    async fn create_vpn_connection_route(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpnConnectionRouteRequest,
    ) -> Result<(), ServiceError> {
        self.create_vpn_connection_route_op(ctx, input)
    }
    async fn delete_vpn_connection_route(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVpnConnectionRouteRequest,
    ) -> Result<(), ServiceError> {
        self.delete_vpn_connection_route_op(ctx, input)
    }
    async fn create_vpc_peering_connection(
        &self,
        ctx: &RequestContext,
        input: types::CreateVpcPeeringConnectionRequest,
    ) -> Result<types::CreateVpcPeeringConnectionResult, ServiceError> {
        self.create_vpc_peering_connection_op(ctx, input)
    }
    async fn accept_vpc_peering_connection(
        &self,
        ctx: &RequestContext,
        input: types::AcceptVpcPeeringConnectionRequest,
    ) -> Result<types::AcceptVpcPeeringConnectionResult, ServiceError> {
        self.accept_vpc_peering_connection_op(ctx, input)
    }
    async fn reject_vpc_peering_connection(
        &self,
        ctx: &RequestContext,
        input: types::RejectVpcPeeringConnectionRequest,
    ) -> Result<types::RejectVpcPeeringConnectionResult, ServiceError> {
        self.reject_vpc_peering_connection_op(ctx, input)
    }
    async fn delete_vpc_peering_connection(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVpcPeeringConnectionRequest,
    ) -> Result<types::DeleteVpcPeeringConnectionResult, ServiceError> {
        self.delete_vpc_peering_connection_op(ctx, input)
    }
    async fn describe_vpc_peering_connections(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcPeeringConnectionsRequest,
    ) -> Result<types::DescribeVpcPeeringConnectionsResult, ServiceError> {
        self.describe_vpc_peering_connections_op(ctx, input)
    }
    async fn modify_vpc_peering_connection_options(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVpcPeeringConnectionOptionsRequest,
    ) -> Result<types::ModifyVpcPeeringConnectionOptionsResult, ServiceError> {
        self.modify_vpc_peering_connection_options_op(ctx, input)
    }
    async fn create_transit_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateTransitGatewayRequest,
    ) -> Result<types::CreateTransitGatewayResult, ServiceError> {
        self.create_transit_gateway_op(ctx, input)
    }
    async fn delete_transit_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransitGatewayRequest,
    ) -> Result<types::DeleteTransitGatewayResult, ServiceError> {
        self.delete_transit_gateway_op(ctx, input)
    }
    async fn describe_transit_gateways(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTransitGatewaysRequest,
    ) -> Result<types::DescribeTransitGatewaysResult, ServiceError> {
        self.describe_transit_gateways_op(ctx, input)
    }
    async fn modify_transit_gateway(
        &self,
        ctx: &RequestContext,
        input: types::ModifyTransitGatewayRequest,
    ) -> Result<types::ModifyTransitGatewayResult, ServiceError> {
        self.modify_transit_gateway_op(ctx, input)
    }
    async fn create_transit_gateway_vpc_attachment(
        &self,
        ctx: &RequestContext,
        input: types::CreateTransitGatewayVpcAttachmentRequest,
    ) -> Result<types::CreateTransitGatewayVpcAttachmentResult, ServiceError> {
        self.create_transit_gateway_vpc_attachment_op(ctx, input)
    }
    async fn delete_transit_gateway_vpc_attachment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransitGatewayVpcAttachmentRequest,
    ) -> Result<types::DeleteTransitGatewayVpcAttachmentResult, ServiceError> {
        self.delete_transit_gateway_vpc_attachment_op(ctx, input)
    }
    async fn describe_transit_gateway_vpc_attachments(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTransitGatewayVpcAttachmentsRequest,
    ) -> Result<types::DescribeTransitGatewayVpcAttachmentsResult, ServiceError> {
        self.describe_transit_gateway_vpc_attachments_op(ctx, input)
    }
    async fn modify_transit_gateway_vpc_attachment(
        &self,
        ctx: &RequestContext,
        input: types::ModifyTransitGatewayVpcAttachmentRequest,
    ) -> Result<types::ModifyTransitGatewayVpcAttachmentResult, ServiceError> {
        self.modify_transit_gateway_vpc_attachment_op(ctx, input)
    }
    async fn accept_transit_gateway_vpc_attachment(
        &self,
        ctx: &RequestContext,
        input: types::AcceptTransitGatewayVpcAttachmentRequest,
    ) -> Result<types::AcceptTransitGatewayVpcAttachmentResult, ServiceError> {
        self.accept_transit_gateway_vpc_attachment_op(ctx, input)
    }
    async fn reject_transit_gateway_vpc_attachment(
        &self,
        ctx: &RequestContext,
        input: types::RejectTransitGatewayVpcAttachmentRequest,
    ) -> Result<types::RejectTransitGatewayVpcAttachmentResult, ServiceError> {
        self.reject_transit_gateway_vpc_attachment_op(ctx, input)
    }
    async fn create_transit_gateway_peering_attachment(
        &self,
        ctx: &RequestContext,
        input: types::CreateTransitGatewayPeeringAttachmentRequest,
    ) -> Result<types::CreateTransitGatewayPeeringAttachmentResult, ServiceError> {
        self.create_transit_gateway_peering_attachment_op(ctx, input)
    }
    async fn accept_transit_gateway_peering_attachment(
        &self,
        ctx: &RequestContext,
        input: types::AcceptTransitGatewayPeeringAttachmentRequest,
    ) -> Result<types::AcceptTransitGatewayPeeringAttachmentResult, ServiceError> {
        self.accept_transit_gateway_peering_attachment_op(ctx, input)
    }
    async fn reject_transit_gateway_peering_attachment(
        &self,
        ctx: &RequestContext,
        input: types::RejectTransitGatewayPeeringAttachmentRequest,
    ) -> Result<types::RejectTransitGatewayPeeringAttachmentResult, ServiceError> {
        self.reject_transit_gateway_peering_attachment_op(ctx, input)
    }
    async fn delete_transit_gateway_peering_attachment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransitGatewayPeeringAttachmentRequest,
    ) -> Result<types::DeleteTransitGatewayPeeringAttachmentResult, ServiceError> {
        self.delete_transit_gateway_peering_attachment_op(ctx, input)
    }
    async fn describe_transit_gateway_peering_attachments(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTransitGatewayPeeringAttachmentsRequest,
    ) -> Result<types::DescribeTransitGatewayPeeringAttachmentsResult, ServiceError> {
        self.describe_transit_gateway_peering_attachments_op(ctx, input)
    }
    async fn describe_transit_gateway_attachments(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTransitGatewayAttachmentsRequest,
    ) -> Result<types::DescribeTransitGatewayAttachmentsResult, ServiceError> {
        self.describe_transit_gateway_attachments_op(ctx, input)
    }
    async fn create_transit_gateway_route_table(
        &self,
        ctx: &RequestContext,
        input: types::CreateTransitGatewayRouteTableRequest,
    ) -> Result<types::CreateTransitGatewayRouteTableResult, ServiceError> {
        self.create_transit_gateway_route_table_op(ctx, input)
    }
    async fn delete_transit_gateway_route_table(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransitGatewayRouteTableRequest,
    ) -> Result<types::DeleteTransitGatewayRouteTableResult, ServiceError> {
        self.delete_transit_gateway_route_table_op(ctx, input)
    }
    async fn describe_transit_gateway_route_tables(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTransitGatewayRouteTablesRequest,
    ) -> Result<types::DescribeTransitGatewayRouteTablesResult, ServiceError> {
        self.describe_transit_gateway_route_tables_op(ctx, input)
    }
    async fn associate_transit_gateway_route_table(
        &self,
        ctx: &RequestContext,
        input: types::AssociateTransitGatewayRouteTableRequest,
    ) -> Result<types::AssociateTransitGatewayRouteTableResult, ServiceError> {
        self.associate_transit_gateway_route_table_op(ctx, input)
    }
    async fn disassociate_transit_gateway_route_table(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateTransitGatewayRouteTableRequest,
    ) -> Result<types::DisassociateTransitGatewayRouteTableResult, ServiceError> {
        self.disassociate_transit_gateway_route_table_op(ctx, input)
    }
    async fn enable_transit_gateway_route_table_propagation(
        &self,
        ctx: &RequestContext,
        input: types::EnableTransitGatewayRouteTablePropagationRequest,
    ) -> Result<types::EnableTransitGatewayRouteTablePropagationResult, ServiceError> {
        self.enable_transit_gateway_route_table_propagation_op(ctx, input)
    }
    async fn disable_transit_gateway_route_table_propagation(
        &self,
        ctx: &RequestContext,
        input: types::DisableTransitGatewayRouteTablePropagationRequest,
    ) -> Result<types::DisableTransitGatewayRouteTablePropagationResult, ServiceError> {
        self.disable_transit_gateway_route_table_propagation_op(ctx, input)
    }
    async fn get_transit_gateway_route_table_associations(
        &self,
        ctx: &RequestContext,
        input: types::GetTransitGatewayRouteTableAssociationsRequest,
    ) -> Result<types::GetTransitGatewayRouteTableAssociationsResult, ServiceError> {
        self.get_transit_gateway_route_table_associations_op(ctx, input)
    }
    async fn get_transit_gateway_route_table_propagations(
        &self,
        ctx: &RequestContext,
        input: types::GetTransitGatewayRouteTablePropagationsRequest,
    ) -> Result<types::GetTransitGatewayRouteTablePropagationsResult, ServiceError> {
        self.get_transit_gateway_route_table_propagations_op(ctx, input)
    }
    async fn get_transit_gateway_attachment_propagations(
        &self,
        ctx: &RequestContext,
        input: types::GetTransitGatewayAttachmentPropagationsRequest,
    ) -> Result<types::GetTransitGatewayAttachmentPropagationsResult, ServiceError> {
        self.get_transit_gateway_attachment_propagations_op(ctx, input)
    }
    async fn create_transit_gateway_route(
        &self,
        ctx: &RequestContext,
        input: types::CreateTransitGatewayRouteRequest,
    ) -> Result<types::CreateTransitGatewayRouteResult, ServiceError> {
        self.create_transit_gateway_route_op(ctx, input)
    }
    async fn delete_transit_gateway_route(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransitGatewayRouteRequest,
    ) -> Result<types::DeleteTransitGatewayRouteResult, ServiceError> {
        self.delete_transit_gateway_route_op(ctx, input)
    }
    async fn replace_transit_gateway_route(
        &self,
        ctx: &RequestContext,
        input: types::ReplaceTransitGatewayRouteRequest,
    ) -> Result<types::ReplaceTransitGatewayRouteResult, ServiceError> {
        self.replace_transit_gateway_route_op(ctx, input)
    }
    async fn search_transit_gateway_routes(
        &self,
        ctx: &RequestContext,
        input: types::SearchTransitGatewayRoutesRequest,
    ) -> Result<types::SearchTransitGatewayRoutesResult, ServiceError> {
        self.search_transit_gateway_routes_op(ctx, input)
    }
    async fn create_flow_logs(
        &self,
        ctx: &RequestContext,
        input: types::CreateFlowLogsRequest,
    ) -> Result<types::CreateFlowLogsResult, ServiceError> {
        self.create_flow_logs_op(ctx, input)
    }
    async fn delete_flow_logs(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFlowLogsRequest,
    ) -> Result<types::DeleteFlowLogsResult, ServiceError> {
        self.delete_flow_logs_op(ctx, input)
    }
    async fn describe_flow_logs(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFlowLogsRequest,
    ) -> Result<types::DescribeFlowLogsResult, ServiceError> {
        self.describe_flow_logs_op(ctx, input)
    }
    async fn associate_subnet_cidr_block(
        &self,
        ctx: &RequestContext,
        input: types::AssociateSubnetCidrBlockRequest,
    ) -> Result<types::AssociateSubnetCidrBlockResult, ServiceError> {
        self.associate_subnet_cidr_block_op(ctx, input)
    }
    async fn disassociate_subnet_cidr_block(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateSubnetCidrBlockRequest,
    ) -> Result<types::DisassociateSubnetCidrBlockResult, ServiceError> {
        self.disassociate_subnet_cidr_block_op(ctx, input)
    }
    async fn create_subnet_cidr_reservation(
        &self,
        ctx: &RequestContext,
        input: types::CreateSubnetCidrReservationRequest,
    ) -> Result<types::CreateSubnetCidrReservationResult, ServiceError> {
        self.create_subnet_cidr_reservation_op(ctx, input)
    }
    async fn delete_subnet_cidr_reservation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSubnetCidrReservationRequest,
    ) -> Result<types::DeleteSubnetCidrReservationResult, ServiceError> {
        self.delete_subnet_cidr_reservation_op(ctx, input)
    }
    async fn get_subnet_cidr_reservations(
        &self,
        ctx: &RequestContext,
        input: types::GetSubnetCidrReservationsRequest,
    ) -> Result<types::GetSubnetCidrReservationsResult, ServiceError> {
        self.get_subnet_cidr_reservations_op(ctx, input)
    }
    async fn assign_private_ip_addresses(
        &self,
        ctx: &RequestContext,
        input: types::AssignPrivateIpAddressesRequest,
    ) -> Result<types::AssignPrivateIpAddressesResult, ServiceError> {
        self.assign_private_ip_addresses_op(ctx, input)
    }
    async fn unassign_private_ip_addresses(
        &self,
        ctx: &RequestContext,
        input: types::UnassignPrivateIpAddressesRequest,
    ) -> Result<(), ServiceError> {
        self.unassign_private_ip_addresses_op(ctx, input)
    }
    async fn assign_ipv6_addresses(
        &self,
        ctx: &RequestContext,
        input: types::AssignIpv6AddressesRequest,
    ) -> Result<types::AssignIpv6AddressesResult, ServiceError> {
        self.assign_ipv6_addresses_op(ctx, input)
    }
    async fn unassign_ipv6_addresses(
        &self,
        ctx: &RequestContext,
        input: types::UnassignIpv6AddressesRequest,
    ) -> Result<types::UnassignIpv6AddressesResult, ServiceError> {
        self.unassign_ipv6_addresses_op(ctx, input)
    }
    async fn describe_network_interface_attribute(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNetworkInterfaceAttributeRequest,
    ) -> Result<types::DescribeNetworkInterfaceAttributeResult, ServiceError> {
        self.describe_network_interface_attribute_op(ctx, input)
    }
    async fn modify_vpc_tenancy(
        &self,
        ctx: &RequestContext,
        input: types::ModifyVpcTenancyRequest,
    ) -> Result<types::ModifyVpcTenancyResult, ServiceError> {
        self.modify_vpc_tenancy_op(ctx, input)
    }
    async fn get_security_groups_for_vpc(
        &self,
        ctx: &RequestContext,
        input: types::GetSecurityGroupsForVpcRequest,
    ) -> Result<types::GetSecurityGroupsForVpcResult, ServiceError> {
        self.get_security_groups_for_vpc_op(ctx, input)
    }
    async fn describe_vpc_classic_link(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcClassicLinkRequest,
    ) -> Result<types::DescribeVpcClassicLinkResult, ServiceError> {
        self.describe_vpc_classic_link_op(ctx, input)
    }
    async fn describe_vpc_classic_link_dns_support(
        &self,
        ctx: &RequestContext,
        input: types::DescribeVpcClassicLinkDnsSupportRequest,
    ) -> Result<types::DescribeVpcClassicLinkDnsSupportResult, ServiceError> {
        self.describe_vpc_classic_link_dns_support_op(ctx, input)
    }
    async fn enable_vpc_classic_link(
        &self,
        ctx: &RequestContext,
        input: types::EnableVpcClassicLinkRequest,
    ) -> Result<types::EnableVpcClassicLinkResult, ServiceError> {
        self.enable_vpc_classic_link_op(ctx, input)
    }
    async fn disable_vpc_classic_link(
        &self,
        ctx: &RequestContext,
        input: types::DisableVpcClassicLinkRequest,
    ) -> Result<types::DisableVpcClassicLinkResult, ServiceError> {
        self.disable_vpc_classic_link_op(ctx, input)
    }
    async fn describe_instance_credit_specifications(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceCreditSpecificationsRequest,
    ) -> Result<types::DescribeInstanceCreditSpecificationsResult, ServiceError> {
        self.describe_instance_credit_specifications_op(ctx, input)
    }
    async fn modify_instance_credit_specification(
        &self,
        ctx: &RequestContext,
        input: types::ModifyInstanceCreditSpecificationRequest,
    ) -> Result<types::ModifyInstanceCreditSpecificationResult, ServiceError> {
        self.modify_instance_credit_specification_op(ctx, input)
    }
    async fn get_password_data(
        &self,
        ctx: &RequestContext,
        input: types::GetPasswordDataRequest,
    ) -> Result<types::GetPasswordDataResult, ServiceError> {
        self.get_password_data_op(ctx, input)
    }
    async fn get_instance_uefi_data(
        &self,
        ctx: &RequestContext,
        input: types::GetInstanceUefiDataRequest,
    ) -> Result<types::GetInstanceUefiDataResult, ServiceError> {
        self.get_instance_uefi_data_op(ctx, input)
    }
    // Spot Instances, Spot Fleet, EC2 Fleet, Dedicated Hosts and Reserved Instances
    async fn request_spot_instances(
        &self,
        ctx: &RequestContext,
        input: types::RequestSpotInstancesRequest,
    ) -> Result<types::RequestSpotInstancesResult, ServiceError> {
        self.request_spot_instances_op(ctx, input).await
    }
    async fn describe_spot_instance_requests(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSpotInstanceRequestsRequest,
    ) -> Result<types::DescribeSpotInstanceRequestsResult, ServiceError> {
        self.describe_spot_instance_requests_op(ctx, input).await
    }
    async fn cancel_spot_instance_requests(
        &self,
        ctx: &RequestContext,
        input: types::CancelSpotInstanceRequestsRequest,
    ) -> Result<types::CancelSpotInstanceRequestsResult, ServiceError> {
        self.cancel_spot_instance_requests_op(ctx, input).await
    }
    async fn describe_spot_price_history(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSpotPriceHistoryRequest,
    ) -> Result<types::DescribeSpotPriceHistoryResult, ServiceError> {
        self.describe_spot_price_history_op(ctx, input)
    }
    async fn request_spot_fleet(
        &self,
        ctx: &RequestContext,
        input: types::RequestSpotFleetRequest,
    ) -> Result<types::RequestSpotFleetResponse, ServiceError> {
        self.request_spot_fleet_op(ctx, input).await
    }
    async fn describe_spot_fleet_requests(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSpotFleetRequestsRequest,
    ) -> Result<types::DescribeSpotFleetRequestsResponse, ServiceError> {
        self.describe_spot_fleet_requests_op(ctx, input).await
    }
    async fn describe_spot_fleet_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSpotFleetInstancesRequest,
    ) -> Result<types::DescribeSpotFleetInstancesResponse, ServiceError> {
        self.describe_spot_fleet_instances_op(ctx, input).await
    }
    async fn describe_spot_fleet_request_history(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSpotFleetRequestHistoryRequest,
    ) -> Result<types::DescribeSpotFleetRequestHistoryResponse, ServiceError> {
        self.describe_spot_fleet_request_history_op(ctx, input).await
    }
    async fn modify_spot_fleet_request(
        &self,
        ctx: &RequestContext,
        input: types::ModifySpotFleetRequestRequest,
    ) -> Result<types::ModifySpotFleetRequestResponse, ServiceError> {
        self.modify_spot_fleet_request_op(ctx, input).await
    }
    async fn cancel_spot_fleet_requests(
        &self,
        ctx: &RequestContext,
        input: types::CancelSpotFleetRequestsRequest,
    ) -> Result<types::CancelSpotFleetRequestsResponse, ServiceError> {
        self.cancel_spot_fleet_requests_op(ctx, input).await
    }
    async fn create_fleet(
        &self,
        ctx: &RequestContext,
        input: types::CreateFleetRequest,
    ) -> Result<types::CreateFleetResult, ServiceError> {
        self.create_fleet_op(ctx, input).await
    }
    async fn describe_fleets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFleetsRequest,
    ) -> Result<types::DescribeFleetsResult, ServiceError> {
        self.describe_fleets_op(ctx, input).await
    }
    async fn describe_fleet_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFleetInstancesRequest,
    ) -> Result<types::DescribeFleetInstancesResult, ServiceError> {
        self.describe_fleet_instances_op(ctx, input).await
    }
    async fn describe_fleet_history(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFleetHistoryRequest,
    ) -> Result<types::DescribeFleetHistoryResult, ServiceError> {
        self.describe_fleet_history_op(ctx, input).await
    }
    async fn modify_fleet(
        &self,
        ctx: &RequestContext,
        input: types::ModifyFleetRequest,
    ) -> Result<types::ModifyFleetResult, ServiceError> {
        self.modify_fleet_op(ctx, input).await
    }
    async fn delete_fleets(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFleetsRequest,
    ) -> Result<types::DeleteFleetsResult, ServiceError> {
        self.delete_fleets_op(ctx, input).await
    }
    async fn allocate_hosts(
        &self,
        ctx: &RequestContext,
        input: types::AllocateHostsRequest,
    ) -> Result<types::AllocateHostsResult, ServiceError> {
        self.allocate_hosts_op(ctx, input)
    }
    async fn describe_hosts(
        &self,
        ctx: &RequestContext,
        input: types::DescribeHostsRequest,
    ) -> Result<types::DescribeHostsResult, ServiceError> {
        self.describe_hosts_op(ctx, input)
    }
    async fn modify_hosts(
        &self,
        ctx: &RequestContext,
        input: types::ModifyHostsRequest,
    ) -> Result<types::ModifyHostsResult, ServiceError> {
        self.modify_hosts_op(ctx, input)
    }
    async fn release_hosts(
        &self,
        ctx: &RequestContext,
        input: types::ReleaseHostsRequest,
    ) -> Result<types::ReleaseHostsResult, ServiceError> {
        self.release_hosts_op(ctx, input)
    }
    async fn modify_instance_placement(
        &self,
        ctx: &RequestContext,
        input: types::ModifyInstancePlacementRequest,
    ) -> Result<types::ModifyInstancePlacementResult, ServiceError> {
        self.modify_instance_placement_op(ctx, input)
    }
    async fn describe_reserved_instances_offerings(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReservedInstancesOfferingsRequest,
    ) -> Result<types::DescribeReservedInstancesOfferingsResult, ServiceError> {
        self.describe_reserved_instances_offerings_op(ctx, input)
    }
    async fn purchase_reserved_instances_offering(
        &self,
        ctx: &RequestContext,
        input: types::PurchaseReservedInstancesOfferingRequest,
    ) -> Result<types::PurchaseReservedInstancesOfferingResult, ServiceError> {
        self.purchase_reserved_instances_offering_op(ctx, input)
    }
    async fn describe_reserved_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReservedInstancesRequest,
    ) -> Result<types::DescribeReservedInstancesResult, ServiceError> {
        self.describe_reserved_instances_op(ctx, input)
    }
}
