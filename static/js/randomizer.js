let numerosDisponibles = [];

function iniciarRandomizador(event) {
    event.preventDefault();
    // Leer límite
    const limite = parseInt(document.getElementById('limite').value) || 20;
    // Leer exclusiones
    const excluirStr = document.getElementById('excluir').value;
    let excluir = excluirStr.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
    // Generar lista de números válidos
    numerosDisponibles = [];
    for (let i = 1; i <= limite; i++) {
        if (!excluir.includes(i)) {
            numerosDisponibles.push(i);
        }
    }
    // Ocultar formulario y mostrar randomizador
    document.getElementById('config-form').style.display = 'none';
    document.getElementById('randomizer-main').style.display = 'flex';
    document.getElementById('numero').textContent = '-';
    document.getElementById('btn-random').disabled = false;
}

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

document.getElementById('config-form').addEventListener('submit', iniciarRandomizador);
document.getElementById('btn-random').addEventListener('click', obtenerNumeroAleatorio);

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('numero').textContent = '-';
    document.getElementById('btn-random').disabled = false;
    document.getElementById('randomizer-main').style.display = 'none';
    document.getElementById('config-form').style.display = 'flex';
}); 