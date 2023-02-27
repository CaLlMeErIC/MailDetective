import re


class CheckMail(object):
    """
    缺少message-id
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 5
        # 规则说明
        self.description = "发现缺少message-id"

    def getReport(self):
        """
        发现缺少message-id
        """
        if "message-id" not in self.reader.toDict():
            self.reader.addTag("发现缺少message-id")
            self.reader.addFlag("MISSING_MID")
            return True, [self.score, self.description]
        return False,[]


