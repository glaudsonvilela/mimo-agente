export function saveFile(name, content, type) {
  if (window.PocoNative?.saveDocument) {
    window.PocoNative.saveDocument(name, type, content);
    return;
  }
  const url = URL.createObjectURL(new Blob([content], {type}));
  const link = document.createElement('a'); link.href = url; link.download = name;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
