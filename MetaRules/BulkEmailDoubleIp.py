import re


class CheckMail(object):
    """
    发现received中包含两个ip地址
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 2.2
        # 规则说明
        self.description = "发现received中包含两个ip地址"

    def getReport(self):
        """
        发现received中包含两个ip地址
        """
        if 'received' not in  self.reader.toDict():
            return False,[]
        received_list = self.reader.toDict().get('received')
        received = ""
        for each_str in received_list:
            received += each_str + " "
        received = received[:-1]

        if re.search(r"from \[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\] by \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} with",
                     received, re.IGNORECASE):
            double_ip_spam_1 = 1
        else:
            double_ip_spam_1 = 0

        if re.search(r"from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+by\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3};", received,
                     re.IGNORECASE):
            double_ip_spam_2 = 1
        else:
            double_ip_spam_2 = 0

        if double_ip_spam_1 or double_ip_spam_2:
            self.reader.addTag("Received出现多个ip")
            self.reader.addFlag("RCVD_DOUBLE_IP_SPAM")
            return True, [self.score, self.description]
        return False, []
