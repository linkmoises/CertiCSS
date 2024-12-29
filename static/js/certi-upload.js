<script>
document.getElementById('afiche_evento').addEventListener('change', function() {
    var fileName = this.files[0] ? this.files[0].name : 'No se ha seleccionado ningún archivo.';
    document.getElementById('file-name').textContent = fileName;
});
</script>