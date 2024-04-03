document.addEventListener('DOMContentLoaded', function () {
    const promptForm = document.querySelector('#prompt_form');
    const imageResult = document.querySelector('#image_result');

    promptForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const promptText = document.querySelector('#prompt_text').value;
        generateImage(promptText);
    });

    function generateImage(promptText) {
        fetch('/generate-images', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                prompt: promptText
            })
        })
        .then(response => response.json())
        .then(data => {
            const imgBox = document.createElement('div');
            imgBox.classList.add('img_box');
            const imgElement = document.createElement('img');
            imgElement.src = 'data:image/png;base64,' + data.image;
            imgBox.appendChild(imgElement);
            imageResult.innerHTML = '';
            imageResult.appendChild(imgBox);
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
});
