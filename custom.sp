control "wafv2_web_acl_logging_enabled" {
    title       = "Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)"
    description = "To help with logging and monitoring within your environment, enable AWS WAF (V2) logging on regional and global web ACLs."
    query       = query.wafv2_web_acl_logging_enabled
  }
  
  query "wafv2_web_acl_logging_enabled" {
    sql = <<-EOQ
      select
        arn as resource,
        case
          when logging_configuration is null then 'alarm'
          else 'ok'
        end as status,
        case
          when logging_configuration is null then title || ' logging disabled.'
          else title || ' logging enabled.'
        end as reason
      from
        aws_wafv2_web_acl;
    EOQ
  }
  
  
  control "wafv2_web_acl_rule_attached" {
    title       = "A WAFV2 web ACL should have at least one rule or rule group"
    description = "This control checks whether a WAFV2 web access control list (web ACL) contains at least one WAF rule or WAF rule group. The control fails if a web ACL does not contain any WAF rules or rule groups."
    query       = query.wafv2_web_acl_rule_attached
    }
  
  
  # Non-Config rule query
  
  query "wafv2_web_acl_rule_attached" {
    sql = <<-EOQ
with rule_group_count as (
  select
    arn,
    count(*) as rule_group_count
  from
    aws_wafv2_web_acl,
    jsonb_array_elements(rules) as r
  where
    r -> 'Statement' -> 'RuleGroupReferenceStatement' ->> 'ARN' is not null
  group by
    arn
)
select
  a.arn as resource,
  case
    when rules is null
    or jsonb_array_length(rules) = 0 then 'alarm'
    else 'ok'
  end as status,
  case
    when rules is null
    or jsonb_array_length(rules) = 0 then title || ' has no attached rules.'
    else title || ' has ' || c.rule_group_count || ' rule group(s) and ' || (jsonb_array_length(rules) - c.rule_group_count) || ' rule(s) attached.'
  end as reason,
  region,
  account_id
from
  aws_wafv2_web_acl as a
  left join rule_group_count as c on c.arn = a.arn;
    EOQ
  }
  
  query "alb_attached_to_waf" {
    sql = <<-EOQ
    with wafv2_with_alb as (
      select
        jsonb_array_elements_text(waf.associated_resources) as arn
      from
        aws_wafv2_web_acl as waf
    )
      select alb.arn as resource, 
      case 
        when alb.arn =  temp.arn then 'ok'
      else 'alarm'
      end as status,
      case 
        when alb.arn =  temp.arn then title || ' has associated WAF'
        else title || ' is not associated with WAF.'
      end as reason,
      region,
      account_id

    from aws_ec2_application_load_balancer as alb
      left join wafv2_with_alb  as temp on alb.arn =  temp.arn;
    EOQ
  }


  control "alb_attached_to_waf" { 
    title       = "Public facing ALB are protected by AWS Web Application Firewall v2 (AWS WAFv2)"
    description = "Ensure public facing ALB are protected by AWS Web Application Firewall v2 "
    query       = query.alb_attached_to_waf
    }
  


control "rds_db_instance_multiple_az_enabled" {
    title       = "RDS DB instance multiple az should be enabled"
    description = "Multi-AZ support in AWS Relational Database Service (AWS RDS) provides enhanced availability and durability for database instances."
    query       = query.rds_db_instance_multiple_az_enabled
  }
  
query "rds_db_instance_multiple_az_enabled" {
    sql = <<-EOQ
      select
  arn as resource,
  case
    when engine ilike any (array [ '%aurora-mysql%', '%aurora-postgres%' ]) then 'skip'
    when multi_az then 'ok'
    else 'alarm'
  end as status,
  case
    when engine ilike any (array [ '%aurora-mysql%', '%aurora-postgres%' ]) then title || ' cluster instance.'
    when multi_az then title || ' Multi-AZ enabled.'
    else title || ' Multi-AZ disabled.'
  end as reason,
  region,
  account_id
  from
  aws_rds_db_instance;
    EOQ
  }
  


  
  benchmark "bpost_custom" {
    title       = "Public facing ALB Architecture"
    description = "Ensure public facing ALB are protected by AWS Web Application Firewall v2"
    children = [
      control.wafv2_web_acl_logging_enabled,
      control.alb_attached_to_waf,
      control.wafv2_web_acl_rule_attached,
      control.rds_db_instance_multiple_az_enabled

    ] 
 }
