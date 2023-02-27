import re
import datetime


class CheckMail(object):
    """
    检查日期是否和received里的一致
    """

    def __init__(self, input_mail=None):
        # 输入的MailReader邮件读取类
        self.reader = input_mail

    @staticmethod
    def isNumber(s):
        """
        判断是否是数字
        """
        try:
            int(s)
            return int(True)
        except ValueError:
            return False

    def filterDate(self, date_str):
        """
        截取日期字符串确保第一位是数字
        """
        count = 0
        while count < len(date_str) and not self.isNumber(date_str[count]):
            count += 1
        return date_str[count:]

    def cutDate(self,date_str):
        """
        截取date字符串确保最后一位是数字
        """
        count=len(date_str)-1
        while count > 0 and not self.isNumber(date_str[count]):
            count -= 1
        return date_str[:count+1]

    def getReport(self):
        """
        比对收到邮件的date和received里最新的date的差距时间，根据
        不同时间返回不同的检测结果
        """
        if 'date' not in self.reader.toDict():
            self.reader.addTag("发现缺少date字段")
            self.reader.addFlag("MISSING_DATE")
            return True, [3, "缺少date"]
        date_list = self.reader.toDict().get('date')
        if len(date_list) > 1:
            self.reader.addTag("存在多个date")
            self.reader.addFlag("MULTI_DATE")
            return True, [3, "存在多个date属性"]
        if 'received' not in self.reader.toDict():
            return False, []

        mail_date = self.filterDate(date_list[0].lstrip())
        mail_date=self.cutDate(mail_date[:20].rstrip())
        received_date = self.filterDate(self.reader.toDict().get('received')[0].split(';')[-1].lstrip())
        received_date=self.cutDate(received_date[:20].rstrip())
        mail_date = datetime.datetime.strptime(mail_date, '%d %b %Y %H:%M:%S')
        received_date = datetime.datetime.strptime(received_date.rstrip(), '%d %b %Y %H:%M:%S')

        if mail_date > received_date:
            # 如果邮件时间在received时间之后
            delay_hour = (mail_date - received_date).seconds // 3600
            if 3 <= delay_hour <= 6:
                self.reader.addTag("邮件时间在received时间之后3-6小时")
                self.reader.addFlag("DATE_IN_FUTURE_03_06")
                return True, [3.3, "邮件时间在received时间之后3-6小时"]
            if 6 <= delay_hour <= 12:
                self.reader.addTag("邮件时间在received时间之后6-12小时")
                self.reader.addFlag("DATE_IN_FUTURE_06_12")
                return True, [2.9, "邮件时间在received时间之后6-12小时"]
            if 12 <= delay_hour <= 24:
                self.reader.addTag("邮件时间在received时间之后12-24小时")
                self.reader.addFlag("DATE_IN_FUTURE_12_24")
                return True, [2.6, "邮件时间在received时间之后12-24小时"]
            if 24 <= delay_hour <= 48:
                self.reader.addTag("邮件时间在received时间之后24-48小时")
                self.reader.addFlag("DATE_IN_FUTURE_24_48")
                return True, [2.6, "邮件时间在received时间之后12-24小时"]
            if 48 <= delay_hour <= 96:
                self.reader.addTag("邮件时间在received时间之后48-96小时")
                self.reader.addFlag("DATE_IN_FUTURE_48_96")
                return True, [2.4, "邮件时间在received时间之后48-96小时"]
            if delay_hour >= 96:
                self.reader.addTag("邮件时间在received时间之后超过96小时")
                self.reader.addFlag("DATE_IN_FUTURE_96_XX")
                return True, [0.5, "邮件时间在received时间之后超过96小时"]

        if mail_date < received_date:
            # 如果邮件时间在received时间之前
            delay_hour = (received_date - mail_date).seconds // 3600
            if 3 <= delay_hour <= 6:
                self.reader.addTag("邮件时间在received时间之前3-6小时")
                self.reader.addFlag("DATE_IN_PAST_03_06")
                return True, [3, "邮件时间在received时间之前3-6小时"]
            if 6 <= delay_hour <= 12:
                self.reader.addTag("邮件时间在received时间之前6-12小时")
                self.reader.addFlag("DATE_IN_PAST_06_12")
                return True, [2, "邮件时间在received时间之前6-12小时"]
            if 12 <= delay_hour <= 24:
                self.reader.addTag("邮件时间在received时间之前12-24小时")
                self.reader.addFlag("DATE_IN_PAST_12_24")
                return True, [0.5, "邮件时间在received时间之前12-24小时"]
            if 24 <= delay_hour <= 48:
                self.reader.addTag("邮件时间在received时间之前24-48小时")
                self.reader.addFlag("DATE_IN_PAST_24_48")
                return True, [1.2, "邮件时间在received时间之前24-48小时"]
            if 48 <= delay_hour <= 96:
                self.reader.addTag("邮件时间在received时间之前48-96小时")
                self.reader.addFlag("DATE_IN_PAST_48_96")
                return True, [0.5, "邮件时间在received时间之前48-96小时"]
            if delay_hour >= 96:
                self.reader.addTag("邮件时间在received时间之前超过96小时")
                self.reader.addFlag("DATE_IN_PAST_96_XX")
                return True, [3, "邮件时间在received时间之前超过96小时"]

        return False, []


