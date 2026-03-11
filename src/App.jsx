import { useEffect, useRef } from 'react';
import './App.css';

function App() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let rays = [];

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      initRays();
    };

    const initRays = () => {
      rays = [];
      const rayCount = Math.floor(canvas.width / 50);
      for (let i = 0; i < rayCount; i++) {
        rays.push({
          x: (i * canvas.width) / rayCount,
          y: canvas.height,
          speed: 0.5 + Math.random() * 1.5,
          width: 20 + Math.random() * 30,
          opacity: 0.1 + Math.random() * 0.3,
          angle: -Math.PI / 4 + (Math.random() * Math.PI) / 8
        });
      }
    };

    const animate = () => {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      rays.forEach(ray => {
        ctx.save();
        ctx.translate(ray.x, ray.y);
        ctx.rotate(ray.angle);

        const gradient = ctx.createLinearGradient(0, 0, 0, -canvas.height);
        gradient.addColorStop(0, `rgba(100, 200, 255, ${ray.opacity})`);
        gradient.addColorStop(1, 'rgba(100, 200, 255, 0)');

        ctx.fillStyle = gradient;
        ctx.fillRect(-ray.width / 2, 0, ray.width, canvas.height);

        ray.y -= ray.speed;
        if (ray.y < -canvas.height) {
          ray.y = canvas.height + 100;
        }

        ctx.restore();
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();
    animate();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="app">
      <canvas ref={canvasRef} className="light-rays" />
      <div className="content">
        <h1 className="title">GridShield</h1>
        <p className="subtitle">Protecting Your Digital Frontier</p>
      </div>
    </div>
  );
}

export default App;
