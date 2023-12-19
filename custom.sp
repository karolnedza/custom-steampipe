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
  
  
  control "wafv2_web_acl_resource_attached" {
    title       = "A WAFV2 web ACL should have at least one resource attached"
    description = "This control checks whether a WAFV2 web access control list (web ACL) contains at least one resource attached. The control fails if a web ACL does not contain any resource attached."
    query       = query.wafv2_web_acl_resource_attached
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
          when rules is null or jsonb_array_length(rules) = 0 then 'alarm'
          else 'ok'
        end as status,
        case
          when rules is null or jsonb_array_length(rules) = 0 then title || ' has no attached rules.'
          else title || ' has ' || c.rule_group_count || ' rule group(s) and ' || (jsonb_array_length(rules) - c.rule_group_count) || ' rule(s) attached.'
        end as reason
      from
        aws_wafv2_web_acl as a
        left join rule_group_count as c on c.arn = a.arn;
    EOQ
  }
  
  query "wafv2_web_acl_resource_attached" {
    sql = <<-EOQ
  
    select
    arn as resource,
    case
      when jsonb_array_length(associated_resources) > 0 then 'ok'
      else 'alarm'
    end as status,
    case
      when jsonb_array_length(associated_resources) > 0 then title || ' has associated resources.'
      else title || ' has no instances registered.'
    end as reason,
    region,
    account_id
  from
    aws_wafv2_web_acl;
  
    EOQ
  }
  
  benchmark "bpost_custom" {
    title       = "1.1.1 WAF deployed on public facing ALB"
    description = "WAF deployed on public facing ALB"
    children = [
      control.wafv2_web_acl_resource_attached,
      control.wafv2_web_acl_logging_enabled

    ] 
 }