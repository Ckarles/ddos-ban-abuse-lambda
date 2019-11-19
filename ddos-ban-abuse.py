import io
import re
import gzip
import datetime as dt
import boto3

BAN_THRESHOLD = 50
IPSET_NAME = 'ddos blacklist'
RULE_NAME = 'match a blacklisted IPSet'

BUCKET_NAME = 'removed-secrets'
PREFIX_ROOTDIR = 'AWSLogs'
PREFIX_ACCOUNTID = 'removed-secrets'
PREFIX_SERVICE = 'elasticloadbalancing'
PREFIX_REGION = 'eu-central-1'
PREFIX_LOADBALANCER_RESSOURCETYPE = 'app'
PREFIX_LOADBALANCER_NAME = 'removed-secrets'
PREFIX_LOADBALANCER_ID = 'removed-secrets'

class Logs:

    def __init__(self, session, datetime=dt.datetime.utcnow()):

        self.resource = session.resource('s3')
        self.bucket = self.resource.Bucket(BUCKET_NAME)
        self.prefix = self.get_logfile_prefix(datetime)

    def __iter__(self):
        """Iterates over each line of the gz-decompressed http stream"""

        for obj in self.bucket.objects.filter(Prefix=self.prefix):
            stream = obj.get()['Body']
            with gzip.GzipFile(fileobj=stream) as bytes:
                with io.TextIOWrapper(bytes) as text:
                    yield from text


    def get_logfile_prefix(self, datetime):
        """Returns the logfile prefix to look for in s3"""

        rounded_dt = self.round_datetime(datetime, minutes=5)

        loadbalancer_resourcepath = '.'.join((
            PREFIX_LOADBALANCER_RESSOURCETYPE,
            PREFIX_LOADBALANCER_NAME,
            PREFIX_LOADBALANCER_ID
        ))

        s3_filename_prefix = '_'.join((
            PREFIX_ACCOUNTID,
            PREFIX_SERVICE,
            PREFIX_REGION,
            loadbalancer_resourcepath,
            rounded_dt.strftime('%Y%m%dT%H%MZ')
        ))

        s3_object_prefix = '/'.join((
            PREFIX_ROOTDIR,
            PREFIX_ACCOUNTID,
            PREFIX_SERVICE,
            PREFIX_REGION,
            rounded_dt.strftime('%Y/%m/%d'),
            s3_filename_prefix
        ))

        return s3_object_prefix


    def round_datetime(self, d, *args, **kwargs):
        """Round a datetime with a specific modulus"""

        td = dt.timedelta(
            hours = d.hour,
            minutes = d.minute,
            seconds = d.second,
            microseconds = d.microsecond
        )
        rounded_td = td - td % dt.timedelta(*args, **kwargs)
        return dt.datetime.combine(d.date(), dt.time(), d.tzinfo) + rounded_td


class IPset:

    def __init__(self, session):
        self.client = session.client('waf-regional')
        self.ipset_name = IPSET_NAME

        self.id = self.get_id()
        if not self.id:
            # if the ipset does not exists, create it and add it to the rule
            self.id = self.create()
            self.add_to_rule()


    def get_id(self):
        """Get the ipset id from the list of ipsets"""

        res = self.client.list_ip_sets()
        for ipset in res['IPSets']:

            # return the ipset id if found
            if ipset['Name'] == self.ipset_name:
                return ipset['IPSetId']

        return None


    def create(self):
        """Create the ipset and returns the id"""

        change_token = self.client.get_change_token()['ChangeToken']
        return self.client.create_ip_set(
            Name = self.ipset_name,
            ChangeToken = change_token
        )['IPSet']['IPSetId']


    def add_to_rule(self):
        """Add the ipset to the WAF rule"""

        # get the rule_id from the list of rules
        res = self.client.list_rules()
        rule_id = [ rule['RuleId'] for rule in res['Rules'] if rule['Name'] == RULE_NAME ][0]

        # add the ipset to the rule
        change_token = self.client.get_change_token()['ChangeToken']
        return self.client.update_rule(
            RuleId = rule_id,
            ChangeToken = change_token,
            Updates = [{
                'Action': 'INSERT',
                'Predicate': {
                    'Negated': False,
                    'Type': 'IPMatch',
                    'DataId': self.id
                }
            }]
        )

    def update(self, ips):
        """Update the IP set with additional ips"""

        self.ips = ips

        change_token = self.client.get_change_token()['ChangeToken']
        return self.client.update_ip_set(
            IPSetId = self.id,
            ChangeToken = change_token,
            Updates = [ {
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': 'IPV4',
                    'Value': ip + '/32'
                }   
            } for ip in ips ]
        )


def lambda_handler(event=None, context=None, session=None):
    """Lambda handler"""

    if not session:
        # code is executed inside aws, create a session
        session = boto3.Session()

    ips = {}
    for line in Logs(session):

        # extract the IP part of the 4th space-delimited content in a line of log
        ip = re.match('^(?:[^ ]+ ){3}(.+?):.*$', line)[1]
        client_version = re.match('^(?:[^"]+"){3}([^"]+)".*$', line)[1]

        if not re.match('Apache-HttpClient\/[^ ]* \(Java\/[^)]*\)', client_version):
            # increment the number of occurence of this ip (default to 0) by 1
            ips[ip] = ips.get(ip, 0) + 1


    # filter the IPs
    # ban if the occurence of the IP reached the threshold limit
    ips_to_ban = [ ip for ip in ips if ips[ip] >= BAN_THRESHOLD ]

    ipset = IPset(session)
    ipset.update(ips_to_ban)
    print('IPs banned: ' + str(ips_to_ban))

    # return mandatory to terminate the lambda
    return ips_to_ban


if __name__ == "__main__":

    session = boto3.Session(profile_name='admin')
    lambda_handler(session=session)
