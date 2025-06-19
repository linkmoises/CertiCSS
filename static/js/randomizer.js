let numerosDisponibles = Array.from({length: 18}, (_, i) => i + 3);

function obtenerNumeroAleatorio() {
    if (numerosDisponibles.length === 0) {
        document.getElementById('numero').textContent = '¡Fin!';
        document.getElementById('btn-random').disabled = true;
        return;
    }
    const idx = Math.floor(Math.random() * numerosDisponibles.length);
    const numero = numerosDisponibles.splice(idx, 1)[0];
    document.getElementById('numero').textContent = numero;
}

document.getElementById('btn-random').addEventListener('click', obtenerNumeroAleatorio);

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('numero').textContent = '-';
    document.getElementById('btn-random').disabled = false;
    numerosDisponibles = Array.from({length: 18}, (_, i) => i + 3);
}); 