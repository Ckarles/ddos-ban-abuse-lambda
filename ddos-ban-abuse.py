import io
import re
import gzip
import datetime as dt
import boto3

BUCKET_NAME = 'removed-secrets'
BAN_THRESHOLD = 50

TEST = True

def gz_stream_to_lines(stream):
    """Iterate over utf-8 lines from a gzip stream of data"""

    with gzip.GzipFile(fileobj=stream) as bytes:
        with io.TextIOWrapper(bytes) as text:
            yield from text

def get_gzip(session, logfile_prefix):
    """Get gzip stream and iterate chunks of gzipped-compressed data"""

    if not TEST:
        s3 = session.resource('s3')
        bucket = s3.Bucket(BUCKET_NAME)
        for s3_object in bucket.objects.filter(Prefix=logfile_prefix):
            yield s3_object.get()['Body']

    else:
        with open('test.log.gz', 'rb') as gz_stream:
            yield gz_stream

def round_datetime(d, *args, **kwargs):
    """Round a datetime with a specific modulus"""

    td = dt.timedelta(
        hours = d.hour,
        minutes = d.minute,
        seconds = d.second,
        microseconds = d.microsecond
    )
    rounded_td = td - td % dt.timedelta(*args, **kwargs)
    return dt.datetime.combine(d.date(), dt.time(), d.tzinfo) + rounded_td


def ban_abuse(session):
    """Lambda handler"""

    now = dt.datetime.utcnow()
    logfile_datetime = round_datetime(now, minutes=5)

    logfile_prefix = 'AWSLogs/removed-secrets/elasticloadbalancing/eu-central-1/' + logfile_datetime.strftime('%Y/%m/%d') + '/removed-secrets_elasticloadbalancing_eu-central-1_removed-secrets-removed-secrets_' + logfile_datetime.strftime('%Y%m%dT%H%MZ')

    ips = {}

    for stream in get_gzip(session, logfile_prefix):
        for line in gz_stream_to_lines(stream):

            # extract the IP part of the 4th space-delimited content in a line of log
            ip = re.match('^(?:[^ ]+ ){3}(.+?):.*$', line)[1]

            # increment the number of occurence of this ip (default to 0) by 1
            ips[ip] = ips.get(ip, 0) + 1

    # filter the IPs
    # ban if the occurence of the IP reached the threshold limit
    banned_ips = [ ip for ip in ips if ips[ip] >= BAN_THRESHOLD ]

    print(banned_ips)


if __name__ == "__main__":

    session = boto3.Session(profile_name='admin') if not TEST else None
    ban_abuse(session)
