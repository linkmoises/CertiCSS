let numerosDisponibles = [];

function iniciarRandomizador(event) {
    event.preventDefault();
    // Leer límites
    const limiteInferior = parseInt(document.getElementById('limite-inferior').value) || 1;
    const limiteSuperior = parseInt(document.getElementById('limite').value) || 20;
    // Validar límites
    if (limiteInferior > limiteSuperior) {
        alert('El límite inferior no puede ser mayor que el superior.');
        return;
    }
    // Leer exclusiones
    const excluirStr = document.getElementById('excluir').value;
    let excluir = excluirStr.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
    // Generar lista de números válidos
    numerosDisponibles = [];
    for (let i = limiteInferior; i <= limiteSuperior; i++) {
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