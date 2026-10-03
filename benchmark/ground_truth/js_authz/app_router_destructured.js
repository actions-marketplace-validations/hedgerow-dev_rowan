export const session = (req) => req.user;
export async function GET(req, { params }) {
  const { id } = params;
  const doc = await Doc.findById(id);
  return NextResponse.json(doc);
}
