chrome.runtime.onMessage.addListener(
    function(request, _, sendResponse) {
        if (request.action === "makeRequest") {
            fetch(request.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({"url": request.data }),
                mode: 'no-cors' 
            })
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => sendResponse({ error: error.message }));
            return true;
        }
    }
);
