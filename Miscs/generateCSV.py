#生成邮件字段的csv字段表格
from OSutils import writeCsv,loadJson
data_head=[("序号","字段名称","出现次数","字段内容举例","说明","样本文件名")]
save_path="result.csv"
answer_data=[]
count_dict=loadJson("paramCount.json")
file_source=loadJson("paramSource.json")
param_example=loadJson("paramExample.json")
count=0
for each_key in sorted(count_dict, key=count_dict.__getitem__, reverse=True):
    count+=1
    appear_num=count_dict.get(each_key)
    if appear_num<50:
        break
    temp=[count,each_key,appear_num,param_example.get(each_key)," ",file_source.get(each_key)]
    if each_key.startswith('X') or each_key.startswith('x'):
        answer_data.append(temp)
    else:
        pass
        #answer_data.append(temp)

writeCsv(answer_data,data_head,save_path)

