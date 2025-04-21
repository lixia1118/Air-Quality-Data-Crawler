import asyncio
import base64
import csv
import hashlib
import json
import logging
import os
import re
import time
from typing import Any
import aiohttp
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm

# === 配置 ===
CITY_FILE = '城市列表.txt'
DATA_DIR = '2013-12至今_全国各城市的空气质量指标'
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class CipherKeysMapper:
    AES = {
        'Encrypt': {'key': "84f8e58a7b19f481", 'iv': "f41de95c205ae7a6"},
        'Decrypt': {'key': "a5dbbe8708dd6c38", 'iv': "86b01ec583dcaaaa"}
    }
    DES = {
        'Encrypt': {'key': "d41d8cd9", 'iv': "ecf8427e"},
        'Decrypt': {'key': "f396fe4d", 'iv': "0b4e0780"}
    }


class DESCipher:
    def __init__(self, key: str, iv: str):
        self.key = key.encode()
        self.iv = iv.encode()

    def decrypt(self, text: str):
        cipher = DES.new(self.key, DES.MODE_CBC, iv=self.iv)
        ciphertext = base64.b64decode(text)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return decrypted_data.decode()


class AESCipher:
    def __init__(self, key: str, iv: str):
        self.key = key.encode()
        self.iv = iv.encode()

    def encrypt(self, text: str):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        padded_text = pad(text.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, text: str):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        ciphertext = base64.b64decode(text)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode("utf-8")


class AsyncAirQuality:
    def __init__(self, cityList: list[str]):
        self.cityList = cityList
        self.failedCities = []
        self.maxConcurrentRequests = 20
        self.header = {
            'User-Agent': 'Mozilla/5.0',
            'Referer': 'https://www.aqistudy.cn/historydata/',
        }
        os.makedirs(DATA_DIR, exist_ok=True)
        self.progress = tqdm(desc="-> 全国空气质量采集中", total=0, colour='green')  # 会在 run() 中更新实际任务数量

    def safeCityName(self, name: str) -> str:
        return re.sub(r'[\\/*?:"<>|]', "_", name)

    def isCityDataExists(self, cityName: str) -> bool:
        safe_name = self.safeCityName(cityName)
        path = os.path.join(DATA_DIR, f'{safe_name}.csv')
        return os.path.exists(path)

    def storeData(self, cityName: str, dataList: list[dict[str, Any]]):
        safe_name = self.safeCityName(cityName)
        path = os.path.join(DATA_DIR, f'{safe_name}.csv')
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['month', 'AQI', 'range', 'level', 'PM2.5', 'PM10', 'CO', 'SO2', 'NO2', 'O3'])
            for d in dataList:
                writer.writerow([
                    d['time_point'], d['aqi'], f'{d["min_aqi"]}~{d["max_aqi"]}', d['quality'],
                    d['pm2_5'], d['pm10'], d['co'], d['so2'], d['no2'], d['o3']
                ])

    def _constructRequestPayload(self, city: str) -> str:
        payload = {
            "appId": "3c9208efcfb2f5b843eec8d96de6d48a",
            "method": "GETMONTHDATA",
            "timestamp": int(time.time() * 1000),
            "clienttype": "WEB",
            "object": {"city": city}
        }

        secret = hashlib.md5(
            (payload['appId'] + payload['method'] + str(payload['timestamp']) +
             payload['clienttype'] + json.dumps(payload['object'], ensure_ascii=False, separators=(',', ':'))).encode()
        ).hexdigest()
        payload['secret'] = secret

        base64_payload = base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()).decode()
        encrypted = AESCipher(**CipherKeysMapper.AES['Encrypt']).encrypt(base64_payload)
        return encrypted

    def _decryptResponse(self, response: str) -> list[dict[str, Any]]:
        step1 = base64.b64decode(response).decode()
        step2 = DESCipher(**CipherKeysMapper.DES['Decrypt']).decrypt(step1)
        step3 = AESCipher(**CipherKeysMapper.AES['Decrypt']).decrypt(step2)
        decoded = base64.b64decode(step3).decode()
        json_data = json.loads(decoded)
        return json_data.get('result', {}).get('data', {}).get('items', [])

    async def fetch(self, session: aiohttp.ClientSession, city: str, sem: asyncio.Semaphore, db_lock: asyncio.Lock):
        async with sem:
            for attempt in range(3):
                try:
                    payload = self._constructRequestPayload(city)
                    async with session.post(
                        "https://www.aqistudy.cn/historydata/api/historyapi.php",
                        data={'hA4Nse2cT': payload}
                    ) as resp:
                        text = await resp.text()
                        data = self._decryptResponse(text)
                        async with db_lock:
                            self.storeData(city, data)
                            self.progress.update()
                        return
                except Exception as e:
                    logging.warning(f"错误抓取 {city} (尝试 {attempt+1}/3): {e}")
                    await asyncio.sleep(1)

            self.failedCities.append(city)
            logging.error(f"最终失败城市: {city}")

    async def run(self):
        semRequest = asyncio.Semaphore(self.maxConcurrentRequests)
        dbLock = asyncio.Lock()

        citiesToFetch = [city for city in self.cityList if not self.isCityDataExists(city)]
        self.progress.reset(total=len(citiesToFetch))

        if len(citiesToFetch) < len(self.cityList):
            skipped = len(self.cityList) - len(citiesToFetch)
            logging.info(f"已跳过 {skipped} 个已存在城市的数据")

        async with aiohttp.ClientSession(headers=self.header) as session:
            tasks = [self.fetch(session, city, semRequest, dbLock) for city in citiesToFetch]
            await asyncio.gather(*tasks)

        self.progress.close()
        if self.failedCities:
            logging.info(f"以下城市抓取失败，请重试: {self.failedCities}")

    def start(self):
        asyncio.run(self.run())


def load_cities_from_file(file_path: str) -> list[str]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


if __name__ == '__main__':
    cities = load_cities_from_file(CITY_FILE)
    aq_collector = AsyncAirQuality(cities)
    aq_collector.start()
