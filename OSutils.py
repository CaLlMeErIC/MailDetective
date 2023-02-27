# -*- coding: utf-8 -*-
# 存放常用的操作函数
import pickle
import csv
import codecs
import os
import json

csv.field_size_limit(500 * 1024 * 1024)


def toNumber(s):
    # 判断是否是数字,返回字符串转化的数字
    try:
        if '.' in s:
            float(s)
            return float(s)
        else:
            int(s)
            return int(s)
    except ValueError:
        return s


def getInputArgs(input_args=None):
    # 输入参数,获取返回的参数字典
    if input_args is None:
        input_args = ['']
    args_dict = {}
    count = 0
    for each_str in input_args:
        if each_str.startswith('--'):
            args_dict.update({each_str[2:]: toNumber(input_args[count + 1])})
        count += 1
    return args_dict


def writeDict2Json(dict_data, save_path="test_dict.json"):
    # 字典保存为json文件
    try:
        if dict_data == {}:
            return
        with open(save_path, 'w',encoding='utf-8') as f:
            json.dump(dict_data, f, indent=4,ensure_ascii=False)
    except Exception as e:
        print("writeDict2Json Error", e)


def loadJson(file_path='FARE_result0.225.pkl.json'):
    # 读取json文件
    with open(file_path, 'r', encoding='utf-8',errors='ignore') as fp:
        json_data = json.load(fp)
    return json_data


def getDirFiles(dir_path="E:\\avclass\\behavior\\behavior", suffix=''):
    # 获取指定文件下所有文件的全路径，返回一个列表
    g = os.walk(dir_path)
    print("正在读取" + dir_path + "下的所有文件路径名")
    print("读取的文件后缀名：" + suffix)

    result_ls = []
    final_path: str

    for path, d, filelist in g:
        for filename in filelist:
            if filename.endswith(suffix):
                final_path = os.path.join(path, filename)
                final_path = final_path.replace('\\', '/')
                # 统一换成/结尾
                result_ls.append(final_path)
    return result_ls


def loadPickle(filename):
    # 读取pickle文件
    if not filename.endswith('.pkl'):
        filename = filename + '.pkl'
    pick_file = open(filename, 'rb')
    list_file = pickle.load(pick_file)
    return list_file


def writePickle(dict_data, filename):
    # 把dict_data以pickle的形式保存
    if not filename.endswith('.pkl'):
        filename = filename + '.pkl'
    pick_file = open(filename, 'wb')
    pickle.dump(dict_data, pick_file)
    pick_file.close()


def readCsv(filename="A_test_data.csv"):
    # 读取csv文件
    full_data = []
    with codecs.open(filename, 'r', encoding='utf_8_sig', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            full_data.append(row)
    return full_data[1:]  # 删去抬头


def writeCsv(answer_data=None, data_head=None, filename='default.csv'):
    # 把数据写入csv文件
    if answer_data is None:
        answer_data = [(0, 0)]
    if data_head is None:
        data_head = [
            ("域名", "域名排名", "家族", "类型")
        ]
    data = data_head + answer_data
    f = codecs.open(filename, 'w', 'utf_8_sig', errors='ignore')
    writer = csv.writer(f)
    for i in data:
        writer.writerow(i)
    f.close()


def updateCountDict(data_dict=None, count_str='hi'):
    # 更新统计字典
    if data_dict is None:
        data_dict = {}
    if count_str in data_dict.keys():
        data_dict.update({count_str: 1 + data_dict.get(count_str)})
    else:
        data_dict.update({count_str: 1})


def updateListDict(data_dict=None, input_str='hi', update_fam='new_fam'):
    # 更新列表字典
    if data_dict is None:
        data_dict = {}
    former_list = data_dict.get(update_fam)
    if former_list is None:
        data_dict.update({update_fam: [input_str]})
    else:
        former_list.append(input_str)
        data_dict.update({update_fam: former_list})


def makeDir(path):
    # 判断路径是否存在
    exist = os.path.exists(path)
    if not exist:
        # 如果不存在，则创建目录（多层）
        os.makedirs(path)
        print(path + '目录创建')
        return True
    else:
        return False
