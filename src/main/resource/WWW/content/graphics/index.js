import * as THREE from "../modules/three.module.js";
import { TrackballControls } from "../modules/TrackballControls.js";
let canvas = document.getElementById("canvas");

let renderer = new THREE.WebGLRenderer({
  canvas: canvas,
  antialias: true,
});
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.setClearColor("darkgray");

let camera = new THREE.PerspectiveCamera(
  45,
  canvas.width / canvas.height,
  1,
  100
);
camera.position.set(0, 0, 5);

let scene = new THREE.Scene();

let material = new THREE.MeshPhongMaterial({
  color: "red",
  specular: 0x555555,
  shininess: 30,
  transparent: true,
  opacity: 0.9,
});

let geometry = new THREE.BoxGeometry(1, 1, 1);

let sphere = new THREE.Mesh(
  new THREE.SphereGeometry(1, 32, 32),
  new THREE.MeshPhongMaterial({
    color: "red",
    specular: 0x555555,
    shininess: 30,
    transparent: true,
    opacity: 1,
    wireframe: true,
  })
);

let element = new THREE.Mesh(geometry, material);

let plane = new THREE.Mesh(
  new THREE.PlaneGeometry(5, 5, 32, 32),
  new THREE.MeshPhongMaterial({
    color: "blue",
    side: THREE.DoubleSide,
    shininess: 30,
    specular: 0x555555,
  })
);

// sphere.translateZ(2);
// sphere.translateY(4);
plane.translateZ(-2);
// plane.rotateX(-Math.PI / 4);
element.translateY(1);
element.translateX(2);

sphere.castShadow = true;
sphere.receiveShadow = true;
plane.castShadow = true;
plane.receiveShadow = true;
element.castShadow = true;
element.receiveShadow = true;

let pointLight = new THREE.PointLight(0xff00ff, 10, 100);
let ambientLight = new THREE.AmbientLight(0x333333);
let DirectionalLight = new THREE.DirectionalLight(0xffffff);
DirectionalLight.position.set(1, 1, 2);
DirectionalLight.castShadow = true;

let controls = new TrackballControls(camera, renderer.domElement);
controls.rotateSpeed = 1.0;
controls.zoomSpeed = 1.2;
controls.panSpeed = 0.8;
controls.keys = ["KeyA", "KeyS", "KeyD"];

scene.add(sphere);
scene.add(ambientLight);
scene.add(DirectionalLight);
scene.add(plane);
scene.add(element);
// scene.add(pointLight);

const clock = new THREE.Clock();

function update(dt) {
  element.rotateY(2 * dt);
  controls.update(dt);
  pointLight.position.copy(sphere.position);
}

function render() {
  renderer.render(scene, camera);
}

function animate() {
  let dt = clock.getDelta();
  update(dt);
  render();
  requestAnimationFrame(animate);
}

animate();
