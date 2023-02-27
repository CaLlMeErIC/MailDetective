import re


class CheckMail(object):
    """
    Received: by and from look like IP addresses
    """

    def __init__(self, input_mail):
        # 输入的MailReader邮件读取类
        self.reader = input_mail
        # 触发规则加的警告分数
        self.score = 2
        # 规则说明
        self.description = "发现received中的by和from包含纯ip地址"

    def getReport(self):
        """
        发现received中包含两个ip地址
        """
        if 'received' not in self.reader.toDict():
            return False,[]

        received_list = self.reader.toDict().get('received')
        received = ""
        for each_str in received_list:
            received += each_str + " "
        received = received[:-1]

        if re.search(
                r"(?:\b(?:from|by)\b.{1,4}\b\d{1,3}[._-]\d{1,3}[._-]\d{1,3}[._-]\d{1,3}(?<!127\.0\.0\.1)\b.{0,4}){2}",
                received, re.IGNORECASE):
            double_ip_loose = 1
        else:
            double_ip_loose = 0
        if double_ip_loose and "RCVD_DOUBLE_IP_SPAM" not in self.reader.flag:
            self.reader.addTag("发现received中的by和from包含纯ip地址")
            self.reader.addFlag("RCVD_DOUBLE_IP_LOOSE")
            return True, [self.score, self.description]
        return False, []
