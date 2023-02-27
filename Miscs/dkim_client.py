# -*- coding:utf-8 -*-
import asyncio

from dkim.asyncsupport import DKIM
from base.logger import logger
from settings import DKIM_LOOKUP_TIMEOUT


class DkimClient(object):

    def __init__(self, dkim_domain):
        self.dkim_domain = dkim_domain

    async def _do_check_dkim(self, mailinfo):   # noqa
        result = {'is_dkim_fake': False}
        try:
            sender = mailinfo.get('sender', '')
            send_domain = sender.strip().split('@')[-1]
            if not self.dkim_domain or send_domain not in self.dkim_domain:
                logger.info("send_domain:%s, dkim_domain:%s" % (send_domain, self.dkim_domain))
                logger.info('skip dkim process !!')
                return result
            has_sign = mailinfo.get('signature_cnt', 0)
            mail_content = mailinfo.get('mail_content', '')
            if has_sign:
                # #  加载/etc/resolv.conf的配置, 设置超时时间
                # dns.resolver.reset_default_resolver()
                # if dns.resolver.default_resolver:
                #     dns.resolver.default_resolver.lifetime = DKIM_LOOKUP_TIMEOUT
                for y in range(has_sign):  # Verify _ALL_ the signatures
                    try:
                        d = DKIM(mail_content)
                        res = await d.verify(idx=y)     # noqa
                    except Exception as e:
                        logger.error("dkim query error {}".format(e))
                        continue
                    if res is False:
                        result['is_dkim_fake'] = True
                        break
            else:
                logger.exception("no signature, {} is fake".format(sender))
                result['is_dkim_fake'] = True
            return result
        except Exception as e:
            logger.exception(e)
            return None

    async def _bulk_query(self, mail_infos):    # noqa
        coros = []
        for mail_info in mail_infos:
            coros.append(asyncio.wait_for(self._do_check_dkim(mail_info), timeout=DKIM_LOOKUP_TIMEOUT))
        return await asyncio.gather(*coros, return_exceptions=True)  # noqa

    def do_query(self, mail_infos):
        loop = asyncio.get_event_loop()
        ret = loop.run_until_complete(self._bulk_query(mail_infos))
        results = []
        for index, item in enumerate(ret):
            if item and not isinstance(item, asyncio.TimeoutError):
                logger.info("dkim query result: %s" % item)
                results.append(item.get('is_dkim_fake', False))
            else:
                logger.warn("dkim query timeout")
                results.append(False)
        return results

    def search(self, mail_infos):
        results = []
        if mail_infos:
            results = self.do_query(mail_infos)
        return results
