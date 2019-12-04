#!/usr/bin/env python3

import io
import zipfile
import argparse
from os import environ as env
import boto3

LAMBDA_NAME = 'ddos-ban-abuse'
EVENT_RULE = 'each-5-minutes'

class Lambda():

    def __init__(self, session, arn):
        self.session = session
        self.client = session.client('lambda')
        self.arn = arn

    def deploy_code(self):
        """Zip the code and deploy it to the lambda"""
        
        # create an empty byte file-like object in memory
        with io.BytesIO() as bytes:

            # write new zipfile in this file
            with zipfile.ZipFile(bytes, mode='x') as zfile:
                # add the code to the zip archive
                zfile.write('ddos-ban-abuse.py')

            # deploy the encoded archive to the lambda
            return self.client.update_function_code(
                FunctionName = self.arn,
                ZipFile = bytes.getvalue()
            )

    @property
    def env_vars(self):
        return self.client.get_function_configuration(FunctionName=self.arn)['Environment']['Variables']

    @env_vars.setter
    def env_vars(self, v):
        self.client.update_function_configuration(
            FunctionName = self.arn,
            Environment = {'Variables': v}
        )

def change_ipset(ipset):
    """Change the BLACKLIST_IPSET_NAME in lambda's environment variables"""
    # get the env variables
    env_var = aws_lambda.env_vars
    print('Replacing BLACKLIST_IPSET_NAME: {} -> {}'.format(env_var['BLACKLIST_IPSET_NAME'], ipset))

    # add the new variables
    env_var['BLACKLIST_IPSET_NAME'] = ipset
    aws_lambda.env_vars = env_var

def parse_args():
    """Return parsed arguments from the invokation"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--profile', help='Profile to use for aws session')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-on', '--enable', help='Enable the lambda by adding the cloudwatch trigger', action='store_true')
    group.add_argument('-off', '--disable', help='Disable the lambda by removing the cloudwatch trigger', action='store_true')
    parser.add_argument('-i', '--ipset', help='Change the lambda blacklist ipset name')
    parser.add_argument('-k', '--skip-deploy', help='Skip deployment of the code', action='store_true')

    return vars(parser.parse_args())

if __name__ == "__main__":

    args = parse_args()

    session = boto3.Session(profile_name=args['profile'])

    region_name = session.region_name
    account_id = session.client("sts").get_caller_identity()['Account']

    lambda_arn = 'arn:aws:lambda:' + region_name + ':' + account_id + ':function:' + LAMBDA_NAME
    aws_lambda = Lambda(session, lambda_arn)

    if not args['skip_deploy']:
        aws_lambda.deploy_code()

    # change the ipset name configuration if requested
    if args['ipset']:
        print('Changing BLACKLIST_IPSET_NAME env variable in lambda configuration')
        change_ipset(args['ipset'])

    if args['enable']:
        print('Adding cloudwatch cron trigger')
        session.client('events').put_targets(
            Rule=EVENT_RULE,
            Targets=[{'Id': LAMBDA_NAME, 'Arn': lambda_arn}]
        )

    elif args['disable']:
        print('Removing cloudwatch cron trigger')
        session.client('events').remove_targets(
            Rule=EVENT_RULE,
            Ids=[LAMBDA_NAME]
        )
