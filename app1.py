from flask import Flask, render_template, request, jsonify
from PIL import Image
from diffusers import StableDiffusionPipeline
import torch
import io
import base64

app = Flask(__name__)

# Load the stable diffusion pipeline
auth_token = "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"
modelid = "CompVis/stable-diffusion-v1-4"
device = "cuda" if torch.cuda.is_available() else "cpu"

pipe = StableDiffusionPipeline.from_pretrained(
    modelid,
    revision="fp16",
    use_auth_token=auth_token
)

pipe.to(device)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-images', methods=['POST'])
def generate_images():
    # Get prompt text from the request
    prompt_text = request.json['prompt']
    # Generate the image
    generated_image = generate_image(prompt_text)
    # Convert the image to base64 string
    img_byte_array = io.BytesIO()
    generated_image.save(img_byte_array, format='PNG')
    img_byte_array = img_byte_array.getvalue()
    img_base64 = base64.b64encode(img_byte_array).decode('utf-8')
    # Return the base64 string
    return jsonify({'image': img_base64})

def generate_image(prompt_text):
    output = pipe(prompt_text, guidance_scale=8.5)
    generated_image = output['images'][0]
    return generated_image

if __name__ == '__main__':
    app.run(debug=True)
