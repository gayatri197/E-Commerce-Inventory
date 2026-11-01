from stegano import lsb
import os

print("Current Folder:")
print(os.getcwd())

try:

    secret = lsb.hide(
        "normal.png",
        "Hidden secret message"
    )

    secret.save("stego.png")

    print("Stego image created successfully")

except Exception as e:

    print("ERROR:")
    print(e)