import csv,os,tqdm,argparse
from tqdm import tqdm
import requests,warnings
import requests.packages,urllib3
requests.packages.urllib3.disable_warnings()

def parseParameters():
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', required=True,
                        help="NSX Username")
    parser.add_argument('--password', required=True,
                        help="NSX user password")
    parser.add_argument('--mgr', required=True,
                        help="NSX Manager IP or FQDN")
    parser.add_argument('--filename', default='nsxt_dfw_backup', required=False, 
                        help="Filename for output,default filename is nsxt_dfw_backup.csv and nsxt_dfw_backup_groupdata.csv")
    parser.add_argument('--group_backup_only', type=bool, default=False, required=False,
                        help="True or False! Whether to back up ns group data only.by default, both rule and group are backed up")

    args=parser.parse_args()
    return args

def nsxt_api_get(url):
    args = parseParameters()
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url=url, headers=headers, auth=(args.username,args.password), verify=False)
    return response      

def main(): 
    args = parseParameters()
    pwd=os.path.dirname(__file__)
    #nsx-t api call to get the list of vm
    url_vmlist = f'https://{args.mgr}/api/v1/fabric/virtual-machines'
    vmrowdata = nsxt_api_get(url_vmlist).json()['results']
    #Column name and vm data to write with csv writer.
    vm_data = []
    #prepare vm info for every object from nsxt_vm_list_api_call
    for i in tqdm(vmrowdata,desc='Processing VM data'):
        vm_tag = i.setdefault('tags',"")
        vm_data.append([i['display_name'],i['power_state'][3:],
                            i['source']['target_display_name'] ,
                            i['tags'] ,
                            i['external_id']])           
    #nsx-t api call to get the list of group
    url_group = f'https://{args.mgr}/policy/api/v1/infra/domains/default/groups'
    grouprowdata = nsxt_api_get(url_group).json()['results']
    #Column name and nsgroup data to write with csv writer.
    fields_group = ["Group_Name","Group_ID","Group_Path","Static_VM_Member","Static_IP_Member","Static_MAC_Member","Group_Segment_Port","Condition_Member_OR","Condition_Member_AND"]
    group_data = []
    Group_list={}
    #prepare group info for every object from nsxt_group_list_api_call
    for i in grouprowdata:
        Group_list[i['id']]=i['display_name']
    for i in tqdm(grouprowdata,desc='Processing and export ns group data'):
        Group_Name = i['display_name']
        Group_ID = i['id']
        Group_Path=i['path']
        resource_type_list=[]
        Static_VM_Member=[]
        Static_IP_Member=[]
        Static_MAC_Member=[]
        Group_Segment_Port=[]
        Condition_Member_OR=[]
        Condition_Member_AND=[]
        expression=i['expression']
        #exp_num=len(expression)
        for n in range(len(expression)):
            #expression[n].setdefault('resource_type',"")
            expression[n].setdefault('external_ids',"")
            expression[n].setdefault('ip_addresses',"")
            expression[n].setdefault('mac_addresses',"")
            expression[n].setdefault('paths',"")
            #resource_type_list.append(expression[n]['resource_type'])
            #c_num=[x for x in range(len(resource_type_list)) if resource_type_list[x] == 'Condition' or resource_type_list[x] == 'ConjunctionOperator']
            if expression[n]['resource_type'] != 'Condition' and expression[n]['resource_type'] != 'NestedExpression' :
                if expression[n]['external_ids'] != "":
                    for vm_id in expression[n]['external_ids'] :
                        vm_memeber=str([x['display_name'] for x in vmrowdata if x['external_id'] == vm_id]).strip('[]\'')
                        Static_VM_Member.append(vm_memeber)
                if expression[n]['ip_addresses'] != "":
                    Static_IP_Member.append(expression[n]['ip_addresses'])
                if expression[n]['mac_addresses'] != "":
                    Static_MAC_Member.append(expression[n]['mac_addresses'])
                if expression[n]['paths'] != "":
                    for group_id in expression[n]['paths']:
                        if "/groups/" in group_id:
                            group_memeber=[Group_list[x] for x in Group_list.keys() if x == group_id.split("/")[-1]]
                            Group_Segment_Port.append(str(group_memeber).strip('[]\''))
                        else: 
                            Group_Segment_Port.append(group_id)
            elif expression[n]['resource_type'] == 'Condition' :
                c_item = str(expression[n]['member_type'])+','+str(expression[n]['key'])+','+str(expression[n]['operator']+','+str(expression[n]['value']))
                Condition_Member_OR.append(c_item)
            elif expression[n]['resource_type'] == 'NestedExpression' :
                for m in expression[n]['expressions'] :
                    if m['resource_type'] == 'Condition' :
                        n_item = str(m['member_type'])+','+str(m['key'])+','+str(m['operator'])+','+str(m['value'])
                        Condition_Member_AND.append(n_item)
        item=Group_Name,Group_ID,Group_Path,str(Static_VM_Member).strip('[]'),str(Static_IP_Member).strip('[]'),str(Static_MAC_Member).strip('[]'),str(Group_Segment_Port).strip('[]'),str(Condition_Member_OR).strip('[]'),str(Condition_Member_AND).strip('[]')
        #print('Group:' + str(Group_Name)  + '  VM:' + str(Static_VM_Member).strip('[]') + '  IP:' + str(Static_IP_Member).strip('[]') + '  MAC:' + str(Static_MAC_Member).strip('[]') + '  Group_Segment_Port:' + str(Group_Segment_Port).strip('[]') + '  Condition_Member_OR:' + str(Condition_Member_OR).strip('[]') + '  Condition_Member_AND:' + str(Condition_Member_AND).strip('[]'))
        group_data.append(item)
    dfw_group_number=len(group_data)            
    ##Writing group data to csv file
    with open(f'{pwd}/{args.filename}_groupdata.csv', 'w') as csvfile: 
        # creating a csv writer object 
        csvwriter = csv.writer(csvfile)  
        # writing the fields 
        csvwriter.writerow(fields_group)   
        # writing the data rows 
        csvwriter.writerows(group_data)
        print(f'   total {dfw_group_number} ns groups has been export to file {pwd}/{args.filename}_groupdata.csv') 

    if args.group_backup_only==False:
        #nsx-t api call to get the dfw policies and rules
        url_policies=f'https://{args.mgr}/policy/api/v1/infra/domains/default/security-policies'
        policyrowdata=nsxt_api_get(url_policies).json()['results']
        dfw_policy_number=len(policyrowdata)
        #Column name and nsgroup data to write with csv writer.
        fields_group = 'policy','rule_name','rule_number','source_groups','destination_groups','services','applied_to','action','direction','is_logged','is_disabled','tag'
        policies_data=[]
        #Writing dfw rules data to csv file
        with open(f'{pwd}/{args.filename}.csv', 'w') as csvfile:
            csvwriter = csv.writer(csvfile)  
            # writing the fields 
            csvwriter.writerow(fields_group)
            rule_data=[] 
            for i in tqdm(policyrowdata,desc='Processing and export polices&rules'):
                policy_id=i['id']
                policy_name=i['display_name']
                policy_applied_to=[]
                for n in i['scope']:
                    if n=='ANY':
                        policy_applied_to=['DFW']
                    else:
                        item=','.join([x[0] for x in group_data if x[2]==n])
                        policy_applied_to.append(item) 
                policy_category=i['category']
                policy_is_stateful=i['stateful']
                policy_is_default=i['is_default']
                #print(f'policy_name: {policy_name:<40} policy_applied_to: {str(policy_applied_to):<40} policy_category: {policy_category:<40} policy_is_stateful: {str(policy_is_stateful):<40} policy_is_default: {str(policy_is_default):<40}')
                policy_item=[f'Name: {policy_name}, Applied_to: {str(policy_applied_to)}, Category: {policy_category}, Is_stateful: {str(policy_is_stateful)}, Is_default: {str(policy_is_default)}',]
                csvwriter.writerow(policy_item)
                policies_data.append(policy_item)
                url_rules=f'https://{args.mgr}/policy/api/v1/infra/domains/default/security-policies/{policy_id}/rules'
                rules=nsxt_api_get(url_rules).json()['results']
                for rule in rules:
                    #rule_policy_name=policy_name
                    rule_id=rule['id']
                    rule_name=rule['display_name']
                    rule_id_number=rule['rule_id']
                    rule_source_groups=[]
                    for n in rule['source_groups']:
                        if n=='ANY':
                            rule_source_groups=['ANY']
                        else:
                            item=','.join([x[0] for x in group_data if x[2]==n])
                            rule_source_groups.append(item)    
                    rule_destination_groups=[]
                    for n in rule['destination_groups']:
                        if n=='ANY':
                            rule_destination_groups=['ANY']
                        else:
                            item=','.join([x[0] for x in group_data if x[2]==n])
                            rule_destination_groups.append(item)
                    rule_services=[]
                    for n in rule['services']:
                        if n=='ANY':
                            rule_services=['ANY']
                        else:
                            item=','.join([x[0] for x in group_data if x[2]==n])
                            rule_services.append(item)            
                    rule_applied_to=[]
                    for n in rule['scope']:
                        if n=='ANY':
                            rule_applied_to=['DFW']
                        else:
                            item=','.join([x[0] for x in group_data if x[2]==n])
                            rule_applied_to.append(item)             
                    rule_action=rule['action']
                    rule_direction=rule['direction']
                    rule_is_logged=rule['logged']
                    rule_is_disabled=rule['disabled']
                    rule_tag=rule.get('tag','')
                    rule_is_default=rule['is_default']
                    #print(f'rule_name: {rule_name:<40} source_groups: {str(rule_source_groups):<40} destination_groups: {str(rule_destination_groups):<40} services: {str(rule_services):<40} action: {rule_action:<40} applied_to: {str(rule_applied_to):<40} direction: {rule_direction:<40}')
                    rule_item='',rule_name,rule_id_number,rule_source_groups,rule_destination_groups,rule_services,rule_applied_to,rule_action,rule_direction,str(rule_is_logged),str(rule_is_disabled),rule_tag
                    csvwriter.writerow(rule_item)
                    rule_data.append(rule_item)
            dfw_rule_number=len(rule_data)
            print(f'   total {dfw_policy_number} dfw policies and {dfw_rule_number} rules has been export to file {pwd}/{args.filename}.csv')
    #return group_data,rule_data,and others infomation

if __name__=="__main__":
    main()