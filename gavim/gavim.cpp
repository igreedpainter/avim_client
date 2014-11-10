#include "gavim.h"
#include <QDateTime>
#include <QDebug>
#include <QScrollBar>

#include <boost/bind.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/thread.hpp>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int pass_cb(char *buf, int size, int rwflag, char *u)
{
	int len;
	const char *tmp;
	printf("Enter pass phrase for \"%s\"\n", u);
	tmp = "test";
	len = strlen(tmp);
	if (len <= 0) return 0;
	if (len > size) len = size;
	memcpy(buf, tmp, len);
	return len;
}

recvThread::~recvThread()
{
	qDebug() << "~recvThread()";
}

void recvThread::run()
{
	qDebug() << "recv_thread::run()";

	OpenSSL_add_all_algorithms();
	boost::shared_ptr<BIO> keyfile(BIO_new_file("test.key", "r"), BIO_free);
	if (!keyfile)
	{
		qDebug() << "can not open test.key";
		//exit(1);
	}
	RSA * rsa_key = PEM_read_bio_RSAPrivateKey(keyfile.get(), 0, (pem_password_cb*)pass_cb, (void*) "test.key");

	boost::shared_ptr<BIO> certfile(BIO_new_file("test.crt", "r"), BIO_free);
	if (!certfile)
	{
		qDebug() << "can not open avim.crt";
		//exit(1);
	}
	X509 * x509_cert = PEM_read_bio_X509(certfile.get(), 0, 0, 0);
	certfile.reset();
	keyfile.reset();

	// ���ӵ� im.avplayer.org:24950
	boost::asio::ip::tcp::resolver resolver(io_service_);
	boost::shared_ptr<boost::asio::ip::tcp::socket> avserver(new boost::asio::ip::tcp::socket(io_service_));
	boost::asio::connect(*avserver, resolver.resolve(boost::asio::ip::tcp::resolver::query("im.avplayer.org", "24950")));

	std::string me_addr = "test@avplayer.org";
	// ���� avtcpif
	// ����һ�� tcp �� avif �豸��Ȼ����ӽ�ȥ
	boost::shared_ptr<avtcpif> avinterface;
	avinterface.reset(new avtcpif(avserver, me_addr, rsa_key, x509_cert));
	avinterface->slave_handshake(0);
	avcore_.add_interface(avinterface);
	// ���·�ɱ�, metricԽ�����ȼ�Խ��
	avcore_.add_route(".+@.+", me_addr, avinterface->get_ifname(), 100);

	// ��Э���첽������Ϣ
	boost::asio::spawn(io_service_, boost::bind(&recvThread::recv_msg, this, _1));
	io_service_.run();
}

void recvThread::recv_msg(boost::asio::yield_context yield_context)
{
	boost::system::error_code ec;
	std::string sender, data;
	for (;;)
	{
		avcore_.async_recvfrom(sender, data, yield_context);
		emit recvReady(QString::fromStdString(sender), QString::fromStdString(data));
		qDebug() << "recv_msg()" << QString::fromStdString(data) << " from " << QString::fromStdString(sender);
	}
}

gavim::gavim(QWidget *parent)
	: avcore_(io_service_)/*, rv_thread_(io_service_, avcore_)*/, QWidget(parent)
{
	ui.setupUi(this);

	recvThread *rv_thread_ = new recvThread(io_service_, avcore_);
	connect(rv_thread_, &recvThread::recvReady, this, &gavim::recvHandle);
	connect(rv_thread_, &recvThread::finished, rv_thread_, &QObject::deleteLater);
	
	//����������Ϣ�߳�
	rv_thread_->start();
}

gavim::~gavim()
{
	qDebug() << "~gavim()";
	io_service_.stop();
}

QString gavim::getMessage()
{
	//QString msg = ui.messageTextEdit->toHtml();
	QString msg = ui.messageTextEdit->toPlainText();
	ui.messageTextEdit->clear();
	ui.messageTextEdit->setFocus();
	return msg;
}

void gavim::on_sendButton_clicked()
{
	qDebug() << "on_sendButton_clicked()";

	if (ui.messageTextEdit->toPlainText() == "")
	{
		//QMessageBox::warning(0, tr("����"), tr("�������ݲ���Ϊ��"), QMessageBox::Ok);
		qDebug() << "cant not send null!";
		return;
	}
	ui.messageBrowser->verticalScrollBar()->setValue(ui.messageBrowser->verticalScrollBar()->maximum());
	std::string curMsg = getMessage().toStdString();
	qDebug() << "getMessage()" << QString::fromStdString(curMsg);
	// ���� IM ���̣�����һ�� test  �� test2@avplayer.org
	boost::async(
		[this,curMsg](){
		qDebug() << "send_msg()" << QString::fromStdString(curMsg);
		//avcore_.sendto("test@avplayer.org", "test, me are testing you stupid avim");
		avcore_.sendto("test@avplayer.org", curMsg);
	}
	);
}

void gavim::on_exitButton_clicked()
{
	qDebug() << "on_exitButton_clicked()";
}

void gavim::recvHandle(const QString &sender, const QString &data)
{
	qDebug() << "handleResults()" << sender << " send: " << data;
	QString time = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
	ui.messageBrowser->setTextColor(Qt::blue);
	ui.messageBrowser->setCurrentFont(QFont("Times New Roman", 12));
	ui.messageBrowser->append("[" + sender + "]" + time);
	ui.messageBrowser->append(data);
}
