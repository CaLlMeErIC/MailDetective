class CheckMail(object):
    """
    规则样板
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 2.5
        # 规则说明
        self.description = "说明"

    def getReport(self):
        """
        检测规则
        """
        if self.reader:
            # 如果触发规则，就返回True,对应的警告分数和警告描述
            # 同时给邮件添加标签，默认是规则的描述
            self.reader.addTag(self.description)
            # 给邮件添加flag,用于之后组合规则的检测
            self.reader.addFlag("TEST")
            return True, [self.score, self.description]
        return False, []
