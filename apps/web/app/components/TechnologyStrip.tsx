import styles from "./TechnologyStrip.module.css";

const technologies = [
  { name: "Cloudflare", role: "Performance & security", mark: "cloudflare" },
  { name: "Stripe", role: "Secure payments", mark: "stripe" },
  { name: "OpenAI", role: "AI-assisted analysis", mark: "openai" },
];

export function TechnologyStrip() {
  return (
    <section
      className={`wrap ${styles.section}`}
      aria-labelledby="technology-heading"
    >
      <h2 id="technology-heading" className={styles.label}>
        Built with
      </h2>
      <ul className={styles.strip}>
        {technologies.map((technology) => (
          <li key={technology.name}>
            <span
              className={`${styles.mark} ${styles[technology.mark]}`}
              style={{ maskImage: `url(/brands/${technology.mark}.svg)` }}
              aria-hidden="true"
            />
            <div>
              <h3>{technology.name}</h3>
              <p>{technology.role}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
