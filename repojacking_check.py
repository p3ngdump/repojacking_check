import requests
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class Repojacking_CheckMon:
    def verify(self, url):
        response = requests.get(url)
        if response.url != url:
            return True
        return False

    def critical(self, url):
        tmp = url.split("/")
        target_url = f"{tmp[0]}//{tmp[2]}/{tmp[3]}"
        response = requests.get(target_url)
        if response.status_code == 404:
            return True
        return False

    # Check if the url is repojacking vulnerable/critical
    def check(self, url):
        if self.verify(url):
            if self.critical(url):
                return f"{url} is repojacking critical"
            return f"{url} is repojacking vulnerable"
        return f"{url} is safe"

    # Check if the urls in the file are repojacking vulnerable/critical
    def mass_check(self, path):
        critical_list = []
        vulnerable_list = []
        with open(path, "r") as f:
            for line in f:
                line = line.rstrip("\n")
                if self.verify(line):
                    if self.critical(line):
                        critical_list.append(line)
                    else:
                        vulnerable_list.append(line)
        return critical_list, vulnerable_list


if __name__ == "__main__":
    checkmon = Repojacking_CheckMon()
    logger.info(checkmon.check("https://github.com/ghtorrent/ghtorrent.org"))
