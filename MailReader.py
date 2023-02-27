import email.header
import os
from email.parser import Parser
import json
import re
from OSutils import loadJson


class MailReader(object):
    """
    用于读取eml文件，并把各个字段保存下来
    使用python3.7内置的email包
    """

    def __init__(self, eml_path="", debug=False):
        """
        初始化属性
        """
        self.raw_email = None
        self.email_content = None
        self.process_log = ""
        self.debug = debug
        self.attribute_dict = {}
        self.mail_text = ""
        self.all_links = []
        self.urls = []
        self.tag = set()
        self.flag = set()
        if eml_path:
            self.__MailReader(eml_path)

    @staticmethod
    def decodeHeader(header_str):
        """
        输入需要解码的header字符串，返回解码结果
        """
        temp = email.header.decode_header(header_str)
        result = email.header.make_header(temp)
        return result

    def addTag(self, tag):
        """
        给邮件添加标签,以字符串的形式存放在列表中
        """
        self.tag.add(tag)
        return self.tag

    def addFlag(self, flag):
        """
        给邮件添加自定义的检测标记
        tag用于输出,flag用于规则检测
        """
        self.flag.add(flag)
        return self.flag

    def toString(self):
        """
        打印整个邮件以及日志
        """
        print("email内容:", self.email_content)
        if self.debug:
            print("process_log:", self.process_log)
        return self.email_content

    def toDict(self):
        """
        把header转换为字典形式,From,To,Subject需要单独解码
        字典的键统一小写
        """
        each_key: str
        all_str = []
        if self.attribute_dict != {}:
            return self.attribute_dict

        for each_key in set(self.email_content.keys()):
            self.attribute_dict.update({each_key.lower(): self.email_content.get_all(each_key)})
            all_str += self.email_content.get_all(each_key)

        for each_key in ["From", "To", "Subject"]:
            temp = []
            if each_key not in self.attribute_dict:
                continue
            for each_str in self.attribute_dict.get(each_key):
                each_str = str(self.decodeHeader(each_str))
                temp.append(each_str)
            self.attribute_dict.update({each_key.lower(): temp})
        self.attribute_dict.update({'body': self.getContent()})
        self.attribute_dict.update({'url': self.getUrls()})
        self.attribute_dict.update({'all': all_str})
        return self.attribute_dict

    def toJson(self):
        """
        把字典转换为json格式
        """
        if self.attribute_dict == {}:
            self.attribute_dict = self.toDict()
        return json.dumps(self.attribute_dict)

    def __MailReader(self, eml_path):
        """
        读取邮件，有些邮件开头会混入无用字符，需要去除才能提取信息
        """
        try:
            if os.path.exists(eml_path):
                with open(eml_path, encoding='utf-8', errors='ignore') as fp:
                    self.raw_email = fp.read()
                cut_len = 0
                for each_line in self.raw_email.split('\n'):
                    if ':' not in each_line:
                        cut_len += len(each_line) + 1
                    else:
                        break
                if cut_len:
                    self.raw_email = self.raw_email[cut_len:]
                self.email_content = Parser().parsestr(self.raw_email)
        except Exception as e:
            self.process_log += "读取邮件失败:" + str(e)
            self.toString()
        return self

    def parseMail(self, eml_path):
        """
        输入邮件路径，用email库整理邮件
        """
        self.attribute_dict = {}
        return self.__MailReader(eml_path)

    def getContent(self):
        """
        循环遍历数据块并尝试解码,暂时只处理text数据
        """
        all_content = []
        for par in self.email_content.walk():

            if not par.is_multipart():  # 这里要判断是否是multipart，是的话，里面的数据是无用的
                str_charset = par.get_content_charset(failobj=None)  # 当前数据块的编码信息
                if str_charset is None:
                    self.addTag("没有获取到部分内容的charset")
                    self.addFlag("NO_CHARSET")
                    continue

                str_content_type = par.get_content_type()
                if str_content_type in ('text/plain', 'text/html'):
                    try:
                        content = par.get_payload(decode=True)
                        all_content.append(content.decode(str_charset))
                    except Exception as e:
                        print(e)
        self.mail_text = all_content
        return all_content

    def getUrls(self):
        """
        获取所有的url链接,与getLinks不一样的是,getUrls的返回值是一个字符串列表
        """
        if self.urls:
            return self.urls
        self.getLinks()
        return self.urls

    def getLinks(self):
        """
        通过正则表达式，匹配超链接以及
        显示的属性内容，格式如下
         [('https://rashangharper.com/wp-admin/user/welllz/display/login.html', 'wellsfargo.com')]
        """
        if self.all_links:
            return self.all_links
        all_links = []
        self.urls = []

        if self.mail_text == "":
            self.getContent()

        pattern = '<a.*?href="(.+)".*?>(.*?)</a>'
        for part in self.mail_text:
            links = re.findall(pattern, part, re.IGNORECASE)
            all_links += links

        self.all_links = all_links
        for each_link in all_links:
            self.urls += list(each_link)
        return all_links


if __name__ == '__main__':
    a = MailReader("fakeherf.eml").toDict().get('date')[0]
