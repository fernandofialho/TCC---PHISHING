document.addEventListener("DOMContentLoaded", function () {
    const validateBtn = document.getElementById("validateBtn");
    const urlInput = document.getElementById("urlInput");
    const result = document.getElementById("result");
    const loading = document.getElementById("loading");

    validateBtn.addEventListener("click", async function () {
        const url = urlInput.value.trim();

        if (url === "") {
            result.textContent = "Por favor, insira uma URL válida.";
            return;
        }

        loading.style.display = "block";
        result.textContent = "";
        
        const apiUrl = 'http://phishing-analysis.ddns.net:5000/phishing';

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            console.log('Status da resposta:', response.status);

            if (!response.ok) {
                const errorMessage = await response.text();
                throw new Error('Erro na solicitação: ' + errorMessage);
            }

            const data = await response.json();

            console.log('Resposta da API:', data);

            if (data.is_phishing !== undefined) {
                result.textContent = data.is_phishing ? "Possível URL de phishing." : "URL legítima.";
            } else {
                throw new Error('A resposta da API não contém o atributo "is_phishing" esperado.');
            }
        } catch (error) {
            console.error('Erro ao chamar a API:', error.message);
            result.textContent = "Erro, tente novamente mais tarde.";
        } finally {
            loading.style.display = "none";
        }
    });
});
