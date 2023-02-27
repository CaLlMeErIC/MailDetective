import re


class CheckMail(object):
    """
    Message-Id 具有垃圾邮件中使用的模式
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 2.2
        # 规则说明
        self.description = "Message-Id 具有垃圾邮件中使用的格式"

    def getReport(self):
        """
        Message-Id 具有垃圾邮件中使用的格式
        """
        if 'message-id' not in self.reader.toDict():
            self.reader.addTag("没有message-id")
            self.reader.addFlag("MISSING_MID")
            return True,[5,"没有message-id"]
        message_id_list = self.reader.toDict().get('message-id')
        message_id = ""

        for each_str in message_id_list:
            message_id += each_str + " "
        message_id = message_id[:-1]

        if re.search(r"<[a-z\d][a-z\d\$-]{10,29}[a-z\d]\@[a-z\d][a-z\d.]{3,12}[a-z\d]>", message_id):
            randy = 1
        else:
            randy = 0
        if re.search(r"\b[a-f\d]{8}\b", message_id):
            is_hex = 1
        else:
            is_hex = 0
        if re.search(r"\d{10}", message_id):
            digits = 1
        else:
            digits = 0
        if re.search(r"\@(?:\D{2,}|(?:\d{1,3}\.){3}\d{1,3})>", message_id):
            host = 1
        else:
            host = 0
        if randy and not (is_hex or digits or host):
            self.addTag("Message-id疑似随机生成")
            return True, [self.score, self.description]
        return False, []
