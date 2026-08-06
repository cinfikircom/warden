<!-- Bilerek açıklı fixture — yalnızca test amaçlı. FE-3: Vue v-html sink. -->
<template>
  <div v-html="rawHtml" />
</template>

<script setup>
defineProps({ rawHtml: String });
</script>
