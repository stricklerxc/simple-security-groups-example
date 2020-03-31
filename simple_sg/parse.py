import re
import yaml

from troposphere import Ref
from troposphere.ec2 import SecurityGroup, SecurityGroupIngress

def parse_yaml(file):
    with open(file, 'r') as file_handler:
        return yaml.load(file_handler.read(), Loader=yaml.Loader)

def parse_rule(rule):
    sg_regex = re.compile(
        r"^(udp|tcp|icmp|all|icmpv6)?:?/?/?" # Match Protocol
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}):" # Match CIDR
        r"(\d{1,5})-?(\d{1,5})?"  # Match Ports
    )

    protocol, cidr, from_port, to_port = sg_regex.match(rule).groups()

    if not protocol:
        protocol = 'tcp'
    elif protocol == 'all':
        protocol = '-1'

    if not to_port:
        to_port = from_port

    return (protocol, cidr, int(from_port), int(to_port))

def create_sg(**kwargs):
    sg = SecurityGroup(
        kwargs['id'],
        GroupName=kwargs['name'],
        GroupDescription=kwargs['description']
    )

    return sg

def create_sg_ingress_rules(source_sg, rules):
    rule_objs = []
    for rule in rules:
        _id, definition, description = rule.split(' | ')

        ingress_obj = SecurityGroupIngress(
            f'{source_sg.title}{_id}Ingress',
            Description=description,
            GroupId=Ref(source_sg))

        (ingress_obj.IpProtocol,
         ingress_obj.CidrIp,
         ingress_obj.FromPort,
         ingress_obj.ToPort) = parse_rule(definition)

        rule_objs.append(ingress_obj)

    return rule_objs

