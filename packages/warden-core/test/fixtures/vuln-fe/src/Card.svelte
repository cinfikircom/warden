<!-- Bilerek açıklı fixture — yalnızca test amaçlı. FE-3: Svelte {@html} sink. -->
<script>
  export let description = "";
</script>

<div class="card">
  {@html description}
</div>
