from PIL import Image

def decode_message(image_path):
    """Decode the hidden message from the image using steganography."""
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
    except Exception as e:
        return f"Error loading image: {str(e)}"

    # Initialize an empty string to store the extracted binary message
    extracted_message = ''

    # Extract the LSB (Least Significant Bit) from each pixel value
    pixels = img.load()
    for row in range(img.height):
        for col in range(img.width):
            pixel_value = pixels[col, row]
            for i in range(3):  # For each color channel (RGB)
                extracted_bit = pixel_value[i] & 1  # Get the LSB of the color channel
                extracted_message += str(extracted_bit)
                # Check for end marker every 8 bits
                if len(extracted_message) % 8 == 0:
                    byte = extracted_message[-8:]
                    if byte == '01111110':  # Tilde '~' as end marker in binary
                        break
            else:
                continue
            break
        else:
            continue
        break

    # Convert the extracted binary string into characters
    decoded_message = ''
    for i in range(0, len(extracted_message) - 8, 8):
        byte = extracted_message[i:i+8]
        if len(byte) == 8:  # Ensure it's a valid 8-bit chunk
            decoded_message += chr(int(byte, 2))  # Convert binary to character

    # Return the decoded message without the end marker
    return decoded_message.rstrip('~')

# Example usage:
image_path = "path/to/your/image.png"
message = decode_message(image_path)
print("Decoded message:", message)
