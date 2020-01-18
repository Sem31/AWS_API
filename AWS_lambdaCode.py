import json
import boto3
import logging
import sys
import uuid
import os
import base64
import datetime
import time

# print('Loading : ' + str(__name__))

dynamodb = boto3.resource("dynamodb", region_name='ap-south-1')
table = dynamodb.Table('motf_user_data')

ec2 = boto3.resource('ec2',region_name='ap-south-1')

lambda_response = {
    "isBase64Encoded": False,
    "statusCode": 200,
    "headers": {"access-control-allow-origin": "*"},
    "body": ""
}

'''
Set Logger with corelationid
'''


def setup_logging(uuid):
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)

    h = logging.StreamHandler(sys.stdout)
    # use whatever format you want here
    FORMAT = "%(asctime)s - " + str(__name__) + \
             " - %(levelname)s - %(filename)s:%(lineno)d stage=" + \
             str(os.getenv('stage')) + " correlation_id=" + str(uuid) + " - %(message)s"
    h.setFormatter(logging.Formatter(FORMAT))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)
    return logger


def lambda_handler(event, context):

    if 'corelationid' in event:
        corelationid = event['corelationid']
    else:
        corelationid = str(uuid.uuid4())
        event['corelationid'] = corelationid

    setup_logging(corelationid)
    #logging.info("Entered lambda_handler " + str(event))
    try:
        return main_handler(event, context)
    except Exception as e:
        logging.exception(e)
        logging.error("FAILURE")
        lambda_response["statusCode"] = 500
        lambda_response["body"] = json.dumps({"error":"Internal server error"})
        return lambda_response

def main_handler(event, context):
    #logging.info("Entered main_handler")
    
    
    #login handler
    if event['path'] == "/login":
        return login_handler(event)
    
    if event['path'] == "/status":
        return status_handler(event)
    
    if event['path'] == "/machine":
        return machine_handler(event)
    
    if event['path'] == "/mstatus":
        return machine_status_handler(event)
    
    if event['path'] == "/auth":
        return auth_handler(event)
        
    
    if event['path'] == "/update":
        return updateIp_handler(event)
    
    if event['path'] == "/allowed":
        return allowedIP_handler(event)

'''
update ip in machine and database allowed_ip
'''
def updateIp_handler(event):
    logging.info("Entered updateIp_handler")
    body = json.loads(event['body'])
    print(body)
    for key in ["username"]:
        if key not in body:
            lambda_response["username"] = 401
            lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username or Password"})
            return  lambda_response
    allowed_ip = body["allowed_ip"]
    username = body["username"]
    table_response = table.get_item(Key={'username': username},ConsistentRead=True,)
    machineId = table_response['Item']['machine_id']
    
    try :
        ec3 = boto3.client('ec2')
        ip_instances = ec3.describe_instances(InstanceIds=[machineId])
        security_id = ip_instances['Reservations'][0]['Instances'][0]['SecurityGroups'][0]['GroupId']
        security_response = ec2.SecurityGroup(security_id)
        
        # print(security_response.ip_permissions)
        if security_response.ip_permissions != []:
            security_response.revoke_ingress(IpPermissions=security_response.ip_permissions)
            
        security_response.authorize_ingress(
                    DryRun=False,
                    IpPermissions=[
                        {
                            'FromPort': 3389,
                            'ToPort': 3389,
                            'IpProtocol': 'tcp',
                            'IpRanges': [
                                {
                                    'CidrIp': allowed_ip + "/32",
                                    'Description': 'laabham'
                                },
                            ]}
                    ])
        response = table.update_item(
                Key={
                    'username': username,
                },
                UpdateExpression="set allowed_ip= :allowed_ip",
                ExpressionAttributeValues={
                    ':allowed_ip': allowed_ip,
                },
                ReturnValues="UPDATED_NEW")
            
        lambda_response["statusCode"] = 200
        lambda_response["body"] = json.dumps({'success':True})
        return lambda_response
    except Exception as e:
        logging.exception(e)
        lambda_response["statusCode"] = 401
        lambda_response["body"] = json.dumps({"error": "Invalid Username or Password","success":False})
        return lambda_response
        
'''
check currently allowed_ip
'''
def allowedIP_handler(event):
    try :
        body =event["headers"]
        for key in ["username"]:
            if key not in body:
                lambda_response["statusCode"] = 401
                lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username"})
                return  lambda_response
        username = body["username"]
        # logging.info("username:" +str(username))
        response = table.get_item(Key={'username': username},ConsistentRead=True,)
        # logging.info("username:" +str(response))
        lambda_response["statusCode"] = 200
        lambda_response["body"] = json.dumps({"allowed_ip":response['Item']['allowed_ip']})
        return lambda_response
    except:
        lambda_response["statusCode"] = 200
        lambda_response["body"] = json.dumps({"error":"please pass username in headers"})
        return lambda_response


'''
again password check params (username,password,token)
'''

def auth_handler(event):
    # logging.info("Entered auth_handler")
    body = json.loads(event['body'])
    for key in ["username", "password","token"]:
        if key not in body:
            lambda_response["statusCode"] = 401
            lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username or Password"})
            return  lambda_response
    username = body["username"]
    password = body["password"]
    token = body["token"]
    # logging.info("username:" +str(username))
    # logging.info("password:" +str(password))
    # logging.info("token:" +str(token))
    try:
        response = table.get_item(Key={'username': username},ConsistentRead=True,)
        # print(response["Item"]["encoded_key"])
        # logging.info(str(response))
        # {'Item': {'password': 'abcd#1234', 'username': 'test1234'}, 'ResponseMetadata': {'RequestId': '7JAA7VI73QOS9Q50GVFOTIQORVVV4KQNSO5AEMVJF66Q9ASUAAJG', 'HTTPStatusCode': 200, 'HTTPHeaders': {'server': 'Server', 'date': 'Sat, 14 Dec 2019 12:56:24 GMT', 'content-type': 'application/x-amz-json-1.0', 'content-length': '67', 'connection': 'keep-alive', 'x-amzn-requestid': '7JAA7VI73QOS9Q50GVFOTIQORVVV4KQNSO5AEMVJF66Q9ASUAAJG', 'x-amz-crc32': '3146427920'}, 'RetryAttempts': 0}}
        pas = base64.b64encode(password.encode())
        passw = pas.decode()
        if 'Item' in response and response["Item"]["password"] == passw and response["Item"]["encoded_key"] == token:
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":True})
            return lambda_response
        else:
            #logging.info("user not found or password invalid")
            # raise Exception("UserNotFound")
            lambda_response["body"] = json.dumps({"success":False})
            lambda_response["statusCode"] = 200
            return lambda_response
    except Exception as e:
        logging.exception(e)
        lambda_response["statusCode"] = 401
        lambda_response["body"] = json.dumps({"error": "Invalid Username or Password","success":False})
        return lambda_response
        
'''
machine on/off API
'''
def machine_handler(event):
    # logging.info("Entered machine_handler")
    body = json.loads(event["body"])
    for key in ["status_on"]:
        if key not in body:
            lambda_response["statusCode"] = 401
            lambda_response["body"] = json.dumps({"error": "Invalid keyword"})
            return  lambda_response
    status_on = body["status_on"]
    username = body["username"]
    # logging.info("status_on:" +str(status_on))
    response = table.get_item(Key={'username': username},ConsistentRead=True,)
    machineId = response['Item']['machine_id']
    instance = ec2.Instance(machineId)
    ec3 = boto3.client('ec2')
    ip_instances = ec3.describe_instances(InstanceIds=[machineId])
    status = ip_instances['Reservations'][0]['Instances'][0]['State']['Name']
    # logging.info("response:" +str(response))
    if status_on == "on":
        
        if status == "stopped" or status == "running":
            instance.start()
            time.sleep(6)
            ip = ip_instances['Reservations'][0]['Instances'][0]['PublicIpAddress']
            response = table.update_item(
                    Key={
                        'username': username,
                    },
                    UpdateExpression="set machine_ip= :ip",
                    ExpressionAttributeValues={
                        ':ip': ip,
                    },
                    ReturnValues="UPDATED_NEW")
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":0})
            # logging.info(lambda_response)
            return lambda_response
        elif status == "pending" or status == "stopping" :
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":2})
            return lambda_response
            
    elif status_on == "off":
        if status == "running":
            instance.stop()
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":1})
            # logging.info(lambda_response)
            return lambda_response
        elif status == "pending" or status == "stopping" :
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":2})
            return lambda_response

'''
machine status running/stopped
'''
def machine_status_handler(event):
    try:
        body =event["headers"]
        for key in ["username"]:
            if key not in body:
                lambda_response["statusCode"] = 401
                lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username"})
                return  lambda_response
        username = body["username"]
        #logging.info("username:" +str(username))
        response = table.get_item(Key={'username': username},ConsistentRead=True,)
        machineId = response['Item']['machine_id']
        ec3 = boto3.client('ec2')
        ip_instances = ec3.describe_instances(InstanceIds=[machineId])
        status = ip_instances['Reservations'][0]['Instances'][0]['State']['Name']
        
        if status == "running" or status == "pending":
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":True,"machine" : "currently running"})
            return lambda_response
        if status == "stopping" or status == "stopped":
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":False,"machine" : "currently stopped"})
            return lambda_response
        
    except:
        lambda_response["statusCode"] = 401
        lambda_response["body"] = json.dumps({"error":"please pass username in headers"})
        return lambda_response


'''
database status of machine
'''
def status_handler(event):
    # logging.info("Entered status_handler")
    try:
        body =event["headers"]
        for key in ["username"]:
            if key not in body:
                lambda_response["statusCode"] = 401
                lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username"})
                return  lambda_response
        username = body["username"]
        #logging.info("username:" +str(username))
        response = table.get_item(Key={'username': username},ConsistentRead=True,)
        response['Item'].pop('password')
        response['Item'].pop('machine_id')
        response['Item'].pop('security_id')
        response['Item'].pop('encoded_key')
        # logging.info("username:" +str(response))
        lambda_response["statusCode"] = 200
        lambda_response["body"] = json.dumps(response['Item'])
        return lambda_response
    except:
        lambda_response["statusCode"] = 200
        lambda_response["body"] = json.dumps({"error":"please pass username in headers"})
        return lambda_response
'''
login handler
'''
def login_handler(event):
    #logging.info("Entered login_handler")
    body = json.loads(event['body'])
    # print(body)
    for key in ["username", "password"]:
        if key not in body:
            lambda_response["statusCode"] = 401
            lambda_response["body"] = json.dumps({"success":False,"error": "Invalid Username or Password"})
            return  lambda_response
    username = body["username"]
    password = body["password"]
    #logging.info("username:" +str(username))
    try:
        response = table.get_item(
            Key={
                'username': username
            },
            ConsistentRead=True,
        )
        #logging.info(str(response))
        # {'Item': {'password': 'abcd#1234', 'username': 'test1234'}, 'ResponseMetadata': {'RequestId': '7JAA7VI73QOS9Q50GVFOTIQORVVV4KQNSO5AEMVJF66Q9ASUAAJG', 'HTTPStatusCode': 200, 'HTTPHeaders': {'server': 'Server', 'date': 'Sat, 14 Dec 2019 12:56:24 GMT', 'content-type': 'application/x-amz-json-1.0', 'content-length': '67', 'connection': 'keep-alive', 'x-amzn-requestid': '7JAA7VI73QOS9Q50GVFOTIQORVVV4KQNSO5AEMVJF66Q9ASUAAJG', 'x-amz-crc32': '3146427920'}, 'RetryAttempts': 0}}
        pas = base64.b64encode(password.encode())
        passw = pas.decode()
        if 'Item' in response and response["Item"]["password"] == passw:
            data = username + password
            token = base64.b64encode(data.encode())
            #logging.info(str(token))
            store_token_in_db(username,token.decode())
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"token":token.decode(),"success":True, "username": username})
            return lambda_response
        else:
            #logging.info("user not found or password invalid")
            lambda_response["statusCode"] = 200
            lambda_response["body"] = json.dumps({"success":False,})
            return lambda_response
    except Exception as e:
        logging.exception(e)
        lambda_response["statusCode"] = 401
        lambda_response["body"] = json.dumps({"error": "Invalid Username or Password","success":False})
        return lambda_response

def store_token_in_db(username,encoded_key):
    #logging.info("Entered store_token_in_db :"+str(username))
    #logging.info("Entered store_token_in_db :"+str(encoded_key))
    utc_time = datetime.datetime.utcnow()
    last_login = utc_time.strftime("%Y-%m-%d %H:%M:%S")
    # logging.info("Entered store_token_in_db :"+str(last_login))
    response = table.update_item(
        Key={
            'username': username,
        },
        UpdateExpression="set encoded_key= :encoded_key, last_login =:last_login",
        ExpressionAttributeValues={
            ':encoded_key': encoded_key,
            ':last_login': last_login,
        },
        ReturnValues="UPDATED_NEW"
    )
    
    # logging.info("Update_item : "+str(response))
