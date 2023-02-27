import re

from MailReader import MailReader
from OSutils import loadJson, getDirFiles, writeDict2Json
import importlib


class MailChecker(object):
    """
    用于读取eml文件，并进行检查
    使用python3.7内置的email包
    """

    def __init__(self, eml_path="", debug=False):
        """
        初始化属性
        """

        self.debug = debug
        self.reader = None
        self.report = {}
        self.header_dict = {}
        self.total_score = 0
        if eml_path:
            self.__MailChecker(eml_path)

    def cleanRecord(self):
        """
        清除所有记录
        """
        self.reader = None
        self.report = {}
        self.header_dict = {}
        self.total_score = 0

    def getReport(self):
        """
        打印报告
        """
        if self.report == {}:
            self.checkAll()
        return self.report

    def checkMetaRules(self, rule_path="MetaRules"):
        """
        读取复杂规则的文件夹，使用里面的复杂规则进行检测
        """
        config_dict = loadJson(rule_path + "/rules.config")
        active_rules = config_dict.get('active_rules')
        for each_rule in active_rules:
            try:
                metaclass = importlib.import_module(rule_path + "." + each_rule)
                alarm_flag, report = metaclass.CheckMail(self.reader).getReport()
                if alarm_flag:
                    self.report.update({each_rule: report})
                    score = report[0]
                    self.total_score += score
            except Exception as e:
                print(e)
                continue
        self.report.update({'total_score': self.total_score})
        return self.report

    def RegCheck(self, pattern, re_flag, area):
        """
        使用正则表达式查看邮件的对应部分
        """

        if area not in self.reader.toDict():
            return False
        searcher = re.compile(pattern, re_flag)
        all_str = ""
        for each_str in self.reader.toDict().get(area):
            all_str += each_str + ","
        if searcher.search(all_str) is not None:
            return True
        return False

    def checkJsonRules(self, rule_path="JsonRules"):
        """
        读取简单正则规则的文件夹，使用里面的简单规则进行检测
        """
        config_dict = loadJson(rule_path + "/rules.config")
        active_rules = config_dict.get('active_rules')
        for each_rule in active_rules:
            rule_list = loadJson(rule_path + "/" + each_rule + '.json')
            for rule_dict in rule_list:
                try:
                    re_pattern = rule_dict.get('pattern')
                    flag = 0
                    re_flag = str(rule_dict.get('re.flag'))
                    if "re.i" in re_flag:
                        flag = flag | re.IGNORECASE
                    if "re.m" in re_flag:
                        flag = flag | re.MULTILINE

                    search_area = rule_dict.get('area')
                    if self.RegCheck(re_pattern, flag, search_area):
                        description = rule_dict.get('description')
                        score = rule_dict.get('score')

                        if rule_dict.get("flag"):
                            # 如果有flag就用flag作为报告字典key
                            self.report.update({rule_dict.get("flag"): [score, description]})
                        else:
                            # 否则就使用正则表达式
                            self.report.update({re_pattern: [score, description]})
                        self.total_score += score
                        if rule_dict.get('tag'):
                            self.reader.addTag(rule_dict.get('tag'))
                        if rule_dict.get('flag'):
                            self.reader.addFlag(rule_dict.get('flag'))
                except Exception as e:
                    print(e)
                    continue
        self.report.update({'total_score': self.total_score})
        return self.report

    def checkAll(self, save_path=""):
        """
        进行所有检测
        """
        self.report = {}
        self.checkMetaRules()
        self.checkJsonRules()
        if self.reader.tag:
            self.report.update({"邮件标签": list(self.reader.tag)})
        return self.getReport()

    def __MailChecker(self, eml_path):
        self.report.update({"检测邮件": eml_path})
        self.reader = MailReader(eml_path)
        return self

    def checkFile(self, file_path, save_dir="Report/", verbose=False):
        """
        检测单个文件
        """
        self.cleanRecord()
        self.__MailChecker(file_path)
        file_name = file_path.split('/')[-1]
        file_report = self.checkAll()
        save_path = save_dir + '/' + file_name + "_report.json"
        writeDict2Json(file_report, save_path)
        if verbose:
            print("filename:", file_name)
            print("result:", file_report)

    def checkDir(self, dir_path, save_dir="Report/", verbose=False):
        """
        检测文件夹里的eml文件并保存
        """
        file_list = getDirFiles(dir_path, '.eml')
        for each_file in file_list:
            file_name = each_file.split('/')[-1]
            self.cleanRecord()
            self.__MailChecker(each_file)
            file_report = self.checkAll()
            save_path = save_dir + '/' + file_name + "_report.json"
            writeDict2Json(file_report, save_path)
            if verbose:
                print("filename:", file_name)
                print("result:", file_report)


if __name__ == '__main__':
    MailChecker().checkFile('testfrom.eml', verbose=True)
