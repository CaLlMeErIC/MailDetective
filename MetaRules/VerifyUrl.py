class CheckMail(object):
    """
    检查邮件中，url里显示链接和实际的链接是否一样
    """

    def __init__(self, input_mail):
        self.reader = input_mail
        self.score = 3
        self.description = "邮件html中，实际链接和显示的url不一致"

    @staticmethod
    def isURL(url_str):
        """
        判断字符串是否是url
        """
        for key in ['www.', '.com', 'http:', 'https:']:
            if key in url_str:
                return True
        return False

    def getReport(self):
        all_links = self.reader.getLinks()
        for each_link in all_links:
            url = each_link[0]
            name = each_link[1]

            if self.isURL(name) and name not in url:
                self.reader.addTag("url伪造")
                return True, [self.score, self.description]
        return False, []
