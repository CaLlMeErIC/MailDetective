class CheckMail(object):
    """
    检查邮件中，From是否和存在的真实发件源不一样
    """

    def __init__(self, input_mail):
        self.reader = input_mail
        self.score = 2.5
        self.description = "检查邮件中，From和存在的真实发件源不一样"

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
        检测邮件的From字段,option_sender中是几种可能的
        真实发件人字段
        """

        header_dict = self.reader.toDict()
        if header_dict.get('from'):
            mail_from = self.list2str(header_dict.get('from'))
        else:
            self.reader.addTag("发件人缺失")
            return True, [self.score, "未检测到发件人字段"]

        for option_sender in ["x-mail-from", "return-path", "x-qq-orgsender", "sender"]:
            if option_sender in header_dict:
                for each_option_sender in header_dict.get(option_sender):
                    if each_option_sender not in mail_from:
                        self.reader.addTag("疑似伪造的发件人")
                        return True, [self.score, self.description]
        return False, []
