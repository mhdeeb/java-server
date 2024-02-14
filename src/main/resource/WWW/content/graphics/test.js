import * as THREE from "../modules/three.module.js";
import { OrbitControls } from "../modules/OrbitControls.js";
import { RGBELoader } from "../modules/RGBELoader.js";

function onWindowResize() {
  const width = window.innerWidth;
  const height = window.innerHeight;

  camera.aspect = width / height;
  camera.updateProjectionMatrix();

  renderer.setSize(width, height);
}

function createWorld() {
  window.addEventListener("resize", onWindowResize);
  new RGBELoader().load(
    "textures/kloofendal_43d_clear_puresky_4k.hdr",
    function (texture) {
      texture.mapping = THREE.EquirectangularReflectionMapping;
      scene.background = texture;
      scene.environment = texture;
    }
  );

  const textureLoader = new THREE.TextureLoader();

  const textures = {
    arm: "textures/blue_floor_tiles_01_arm_8k.jpg",
    diffuse: "textures/blue_floor_tiles_01_diff_8k.jpg",
    displacement: "textures/blue_floor_tiles_01_disp_8k.jpg",
    normal: "textures/blue_floor_tiles_01_nor_gl_8k.jpg",
  };

  for (let texture in textures) {
    textures[texture] = textureLoader.load(textures[texture]);
    textures[texture].wrapS = THREE.RepeatWrapping;
    textures[texture].wrapT = THREE.RepeatWrapping;
    textures[texture].repeat.set(10, 10);
  }

  const material = new THREE.MeshStandardMaterial({
    map: textures.diffuse,
    displacementMap: textures.displacement,
    aoMap: textures.arm,
    roughnessMap: textures.arm,
    metalnessMap: textures.arm,
    normalMap: textures.normal,
  });

  let plane = new THREE.Mesh(
    new THREE.PlaneGeometry(100, 100, 1024, 1024),
    material
  );

  plane.rotateX(-Math.PI / 2);
  plane.castShadow = true;
  plane.receiveShadow = true;
  scene.add(plane);
}

let renderer = new THREE.WebGLRenderer({ antialias: true });
renderer.setPixelRatio(window.devicePixelRatio);
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.localClippingEnabled = true;
document.body.appendChild(renderer.domElement);

renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.5;
renderer.outputEncoding = THREE.SRGBColorSpace;

let imageURL = "../image/test.png";

let loader = new THREE.TextureLoader();
let texture = loader.load(imageURL);

let camera = new THREE.PerspectiveCamera(
  45,
  window.innerWidth / window.innerHeight,
  1,
  1000
);

camera.position.set(50, 50, 50);
let light = new THREE.PointLight(0xffffff, 10, 100);
camera.add(light);

let scene = new THREE.Scene();
scene.add(camera);
let material = new THREE.MeshPhongMaterial({
  color: "red",
  specular: 0x555555,
  shininess: 30,
  transparent: true,
  opacity: 0.9,
});

let geometry = new THREE.BoxGeometry(10, 10, 10);

let sphereMaterial = new THREE.MeshPhongMaterial({
  // color: "red",
  specular: 0x555555,
  shininess: 30,
  // transparent: true,
  // opacity: 1,
});
sphereMaterial.map = texture;

let sphere = new THREE.Mesh(
  new THREE.SphereGeometry(1, 32, 32),
  sphereMaterial
);

let element = new THREE.Mesh(geometry, material);

const geometrys = new THREE.BufferGeometry();

const vertices = new Float32Array([
  0, 0, 0, 1, -0.9, -0.5, 1, 0.9, -0.5,

  0, 0, 0, 0.9, 1, -0.5, -0.9, 1, -0.5,

  0, 0, 0, -1, 0.9, -0.5, -1, -0.9, -0.5,

  0, 0, 0, -0.9, -1, -0.5, 0.9, -1, -0.5,
]);

geometrys.setAttribute("position", new THREE.BufferAttribute(vertices, 3));
const materials = new THREE.MeshBasicMaterial({
  color: "#0f1f03",
  side: THREE.DoubleSide,
});

// geometrys.faceVertexUvs = [
//   [
//     [new THREE.Vector2(0, 0), new THREE.Vector2(0, 1), new THREE.Vector2(1, 1)],
//     [new THREE.Vector2(0, 0), new THREE.Vector2(1, 1), new THREE.Vector2(1, 0)],
//     [
//       new THREE.Vector2(0, 0),
//       new THREE.Vector2(1, 0),
//       new THREE.Vector2(0.5, 1),
//     ],
//     [
//       new THREE.Vector2(1, 0),
//       new THREE.Vector2(0, 0),
//       new THREE.Vector2(0.5, 1),
//     ],
//   ],
// ];

// geometrys.setAttribute("uv", new THREE.BufferAttribute(new Float32Array(8), 2));

let textures = loader.load("../image/peta.png");
textures.repeat.set(5, 5);
textures.wrapS = THREE.RepeatWrapping;
textures.wrapT = THREE.RepeatWrapping;

// materials.map = textures;
sphereMaterial.map = textures;

let meshs = new THREE.Mesh(geometrys, materials);

meshs.translateZ(-1);

scene.add(meshs);

// sphere.translateY(4);
// plane.rotateX(-Math.PI / 4);
sphere.translateY(2);

element.translateY(1);
element.translateX(2);

sphere.castShadow = true;
sphere.receiveShadow = true;

element.castShadow = true;
element.receiveShadow = true;

// let pointLight = new THREE.PointLight(0xff00ff, 10, 100);
let ambientLight = new THREE.AmbientLight(0x333333);
let DirectionalLight = new THREE.DirectionalLight(0xffffff);
DirectionalLight.position.set(1, 1, 1);
DirectionalLight.castShadow = true;

let controls = new OrbitControls(camera, renderer.domElement);
controls.rotateSpeed = 1.0;
controls.zoomSpeed = 1.2;
controls.panSpeed = 0.8;
controls.keys = ["KeyA", "KeyS", "KeyD"];

scene.add(sphere);
scene.add(ambientLight);
scene.add(DirectionalLight);
scene.add(element);
// scene.add(pointLight);

const clock = new THREE.Clock();

function update(dt) {
  element.rotateX(2 * dt);
  sphere.rotateY(3 * dt);
  meshs.rotateZ(-3 * dt);
  controls.update(dt);
  // pointLight.position.copy(sphere.position);
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

createWorld();

animate();
