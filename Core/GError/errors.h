#pragma once
#include <QList>
#include <QString>
#include <QTextStream> 

class GError {
public:
	enum Level {
		kWarning = 0,
		kFatal = 1
	};
	GError();
	GError(const Level & type, const QString &descr, const QString &function, const QString &filename, const int &line);
	~GError();

	void Print(QTextStream &stream) const;  // TODO Make default stream = stderr
    explicit operator QString() const;

private:

	Level			level_;
	QString			description_;
	QString			function_;
	QString			filename_;
	int				line_;
};

class GErrorList {
public:
	GErrorList() = default;

	static void	    Add(const GError::Level &level, const QString &descr, const QString &function, const QString &filename, const int &line);
	static GError   Last();
	static void	    Print(QTextStream &stream); // TODO Make default stream = stderr
	static void     Clear();
	

private:
	static QList<GError>	error_list_;
};

#define G_FATAL(description)	GErrorList::Add(GError::kFatal, (description), __FUNCTION__, __FILE__ ,__LINE__)
#define G_WARNING(description)	GErrorList::Add(GError::kWarning, (description), __FUNCTION__, __FILE__, __LINE__)
