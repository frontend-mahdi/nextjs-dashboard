import { fetchCustomers, fetchInvoiceById } from '@/app/lib/data';
import Breadcrumbs from '@/app/ui/invoices/breadcrumbs';
import Form from '@/app/ui/invoices/edit-form';
import { Metadata } from 'next';
import { notFound } from 'next/navigation';

export const metadata: Metadata = {
  title: 'Edit Invoice',
};
export default async function Page({ params }: { params: { id: string } }) {
  const id = params.id;
  console.log(params);
  const [invoice, customers] = await Promise.all([
    fetchInvoiceById(id),
    fetchCustomers(),
  ]);
  if (!invoice) {
    notFound();
  }

  const metadata: Metadata = {
    title: `Edit Invoice #${id}`,
  };
  return (
    <main>
      <Breadcrumbs
        breadcrumbs={[
          { label: 'Invoices', href: '/dashboard/invoices' },
          {
            label: 'Edit Invoice',
            href: `/dashboard/invoices/${id}/edit`,
            active: true,
          },
        ]}
      />
      <Form invoice={invoice} customers={customers} />
    </main>
  );
}
