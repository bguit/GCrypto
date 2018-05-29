#include "errors.h"

// --- GError -----------------------------------------------------------------
GError::GError() :
	level_(kWarning),
	description_(QString()),
	function_(QString()),
	filename_(QString()),
	line_(0) {}
GError::GError(const Level &type, const QString &descr, const QString &function, const QString &filename, const int &line) :
	level_(type),
	description_(descr),
	function_(function),
	filename_(filename),
	line_(line) {}
GError::~GError() = default;

void GError::Print(QTextStream &stream) const {

	if (description_.isEmpty()) return;

	switch (level_) {
	case kFatal:	stream << "Fatal:\t "; break;
	case kWarning:	stream << "Warning: "; break;
	default:		stream << "Success!\n"; return;
	}
	stream.flush();

	stream << "\"" << description_ << "\" in function <" << function_ << "> (" << filename_ << ":" << line_ << "L)\n";
	stream.flush();
}

GError::operator QString() const {
	
	QString ret_string;
	switch (level_) {
	case kFatal:	ret_string = "Fatal:   "; break;
	case kWarning:	ret_string = "Warning: "; break;
	default:		ret_string = "Success!\n"; return ret_string;
	}

	ret_string += QString("%1 in function <%2> (%3:%4L)").arg(description_, function_, filename_, QString::number(line_));

	return ret_string;
}


// --- GErrorList -------------------------------------------------------------
QList<GError> GErrorList::error_list_;

void	GErrorList::Add(const GError::Level& level, const QString& descr, const QString& function, const QString &filename, const int& line) {
	error_list_.append(GError(level, descr, function, filename, line));
}
GError	GErrorList::Last() {
	return error_list_.last();
}

void	GErrorList::Print(QTextStream &stream) {

	if (error_list_.isEmpty()) {
		return;
	}

	stream << "\n--- Error List ---\n";
	for (const auto &error : error_list_) {
		error.Print(stream);
	}
	//stream << "\n";
}

void	GErrorList::Clear() {
	error_list_.clear();
}
