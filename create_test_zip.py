import zipfile
import os

def create_zip():
    os.makedirs('vulnerable_test', exist_ok=True)
    with zipfile.ZipFile('vulnerable.zip', 'w') as zipf:
        zipf.write('vulnerable_test/vulnerable.c', arcname='vulnerable.c')
    print("Created vulnerable.zip")

if __name__ == "__main__":
    create_zip()
