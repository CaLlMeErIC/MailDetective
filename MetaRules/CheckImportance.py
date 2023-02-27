class CheckMail(object):
    """
    邮件被设置了高优先级(常为垃圾邮件)
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 5
        # 规则说明
        self.description = "邮件被设置了高优先级(常为垃圾邮件)"

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
        if 'importance' not in self.reader.toDict():
            return False, []

        mail_rank = self.reader.toDict().get('importance')
        mail_rank = self.list2str(mail_rank).lower()

        if 'high' in mail_rank:
            self.reader.addTag("邮件被设置了高优先级(常为垃圾邮件)")
            self.reader.addFlag("HIGH_IMPORTANCE")
            return True, [self.score, self.description]

        return False, []
