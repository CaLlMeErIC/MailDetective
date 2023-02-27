class CheckMail(object):
    """
    检测如果有校验字段，是否通过校验
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 3
        # 规则说明

    @staticmethod
    def list2str(data_list):
        """
        把字符串列表转换成字符串
        """
        if isinstance(data_list, list):
            result = ""
            for each_str in data_list:
                result += each_str + " "
            return result[:-1]
        return data_list

    def getReport(self):
        """
        检测规则
        """

        if "authentication-results" not in self.reader.toDict():
            return False, []
        verify_result = self.reader.toDict().get("authentication-results")
        verify_result = self.list2str(verify_result).lower()
        if 'spf=fail' in verify_result and 'dkim=fail' in verify_result:
            self.reader.addTag("未通过spf和dkim校验")
            self.reader.addFlag("SPF_DKIM_FAIL")
            return True, [5, "未通过spf和dkim校验"]

        if 'spf=fail' in verify_result:
            self.reader.addTag("未通过spf校验")
            self.reader.addFlag("SPF_FAIL")
            return True, [5, "未通过spf校验"]
        if 'dkim=fail' in verify_result:
            self.reader.addTag("未通过dkim校验")
            self.reader.addFlag("SPF_DKIM_FAIL")
            return True, [5, "未通过dkim校验"]

        return False, []
