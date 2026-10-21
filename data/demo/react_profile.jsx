export function Profile({ user }) {
  return (
    <div>
      <h2>{user.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </div>
  );
}
