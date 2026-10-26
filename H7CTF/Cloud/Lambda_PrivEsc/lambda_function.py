import boto3
import json

def handler(event, context):
    s3 = boto3.client('s3', endpoint_url='https://web-9381bd093af86084.web.h7tex.com')
    sts = boto3.client('sts', endpoint_url='https://web-9381bd093af86084.web.h7tex.com')
    result = {}

    result['identity'] = sts.get_caller_identity()

    try:
        objs = s3.list_objects_v2(Bucket='deputy-runner-logs')
        keys = [o['Key'] for o in objs.get('Contents', [])]
        result['objects'] = keys
        for k in keys:
            body = s3.get_object(Bucket='deputy-runner-logs', Key=k)['Body'].read().decode('utf-8', errors='replace')
            result[k] = body
    except Exception as e:
        result['error'] = str(e)

    return {
        'statusCode': 200,
        'body': json.dumps(result, default=str)
    }
