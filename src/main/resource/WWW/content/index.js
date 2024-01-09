window.addEventListener("DOMContentLoaded", function () {
  let fileUpload = document.getElementById("fileSubmit");
  fileUpload.addEventListener("submit", function (event) {
    event.preventDefault();

    let image = document.getElementById("im");
    let image2 = document.getElementById("im2");
    let placeholder = document.getElementById("placeholder");

    let data = new FormData(event.target);

    if (data.get("file").size == 0) {
      image.style.display = "none";
      image2.style.display = "none";
      placeholder.style.display = "flex";
      return;
    }

    jQuery.ajax({
      type: "POST",
      data: data,
      cache: false,
      contentType: "multipart/form-data",
      processData: false,
      success: function (response) {
        image.style.display = "none";
        image2.style.display = "flex";
      },
    });

    image.style.display = "flex";
    image2.style.display = "none";
    placeholder.style.display = "none";
  });

  let textSubmit = document.getElementById("textSubmit");
  textSubmit.addEventListener("submit", function (event) {
    event.preventDefault();

    const queryString =
      new URLSearchParams(new FormData(event.target)).toString() + "\r\n";

    if (queryString.indexOf("=") == queryString.length - 3) return;

    jQuery.ajax({
      type: "POST",
      data: queryString,
      cache: false,
      contentType: "text/plain",
      processData: false,
      success: function (response) {
        event.target.reset();
      },
    });
  });
});

function light_bonfire() {
  let audio = document.getElementById("sound");
  audio.volume = 0.1;
  audio.play();
  audio.currentTime = 0.9;

  let img = document.getElementById("gif");
  img.style.display = "flex";
  let src = img.src;
  img.src = "";
  img.src = src;
}
