import enum
import os
import shutil
import zipfile
from pathlib import Path

import IP2Location
import requests
from dotenv import load_dotenv
from tqdm import tqdm

IP2LOCATION_URL = "https://www.ip2location.com/download/?token={TOKEN}&file={DATABASE_CODE}"

# load .env
load_dotenv()

IP2LOCATION_TOKEN = os.getenv("IP2LOCATION_TOKEN")
if not IP2LOCATION_TOKEN:
    raise ValueError("Please provide IP2LOCATION_TOKEN environment variable")

db_folder = Path(__file__).parent / "IP2LOCATION"
db_folder.mkdir(parents=True, exist_ok=True)


class I2LDB(enum.Enum):
    pass


for i in [1, 3, 5, 9, 11]:
    for variant in ["BIN", "CSV"]:
        for ip in ["", "IPV6"]:
            setattr(
                I2LDB, f"DB{i}LITE{variant}{ip}",
                {
                    "code": f"DB{i}LITE{variant}{ip}",
                    "file": f"IP2LOCATION-LITE-DB{i}{ip}.{variant}"
                }
            )


class EasyI2LDB:
    def __init__(self, database_code):
        self.database_code = database_code
        self.database_file = None

    def load(self) -> IP2Location.IP2Location:
        return IP2Location.IP2Location(f"{db_folder}/{self.database_code}")


class EasyI2L:
    @staticmethod
    def download(database_code: I2LDB) -> EasyI2LDB:
        # If the file already exists, skip downloading
        if (db_folder / database_code["file"]).exists():
            return EasyI2LDB(database_code["file"])

        url = IP2LOCATION_URL.format(TOKEN=IP2LOCATION_TOKEN, DATABASE_CODE=database_code["code"])
        response = requests.get(url, stream=True)

        # Check if the response is a zip file
        if response.headers.get('Content-Type') != 'application/zip':
            raise ValueError(f"Expected a zip file, but got {response.headers.get('Content-Type')}\n\tUrl: {url}\n\tCode: {response.status_code}\n\tContent: {response.content}")

        if response.status_code == 200:
            total_size = int(response.headers.get('content-length', 0))
            chunk_size = 1024
            with open(f"{database_code['code']}.zip", "wb") as file, tqdm(
                    desc=f"Downloading {database_code['code']}.zip",
                    total=total_size,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
            ) as bar:
                for data in response.iter_content(chunk_size=chunk_size):
                    file.write(data)
                    bar.update(len(data))
            print(f"Downloaded {database_code['code']}.zip")

            with zipfile.ZipFile(f"{database_code['code']}.zip", "r") as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.filename.endswith(('.BIN', '.CSV')):
                        zip_ref.extract(file_info, ".")
                        print(f"Extracted {file_info.filename}")

                        extracted_file = Path(file_info.filename)
                        shutil.move(str(extracted_file), str(db_folder / extracted_file.name))
                        print(f"Moved {extracted_file.name} to {db_folder}")

            print(f"Downloaded and extracted {database_code['code']}.zip")
            Path(f"{database_code['code']}.zip").unlink()

        else:
            raise ValueError(f"Failed to download {database_code['code']}.zip\n\tUrl: {url}\n\tCode: {response.status_code}")

        return EasyI2LDB(database_code['file'])


def main():
    db = EasyI2L.download(I2LDB.DB11LITEBIN).load()

    # tests
    print(db.get_all("1.1.1.1"))


if __name__ == "__main__":
    main()
